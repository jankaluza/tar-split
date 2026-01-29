package asm

import (
	"io"
	"sync/atomic"

	"github.com/vbatts/tar-split/archive/tar"
	"github.com/vbatts/tar-split/tar/storage"
)

// bestEffortPipeWriter delivers bytes into an io.PipeWriter until the consumer
// closes the read-end. After that it pretends writes succeed so tar parsing can
// continue to completion (to finish writing metadata into the packer).
type bestEffortPipeWriter struct {
	pw     *io.PipeWriter
	closed atomic.Bool
}

func (w *bestEffortPipeWriter) Write(p []byte) (int, error) {
	if w.closed.Load() {
		return len(p), nil
	}
	n, err := w.pw.Write(p)
	if err == io.ErrClosedPipe {
		w.closed.Store(true)
		return len(p), nil
	}
	return n, err
}

// runInputTarStream is the shared goroutine body used by both NewInputTarStream
// and NewInputTarStreamWithDone.
//
// It parses the tar stream from outputRdr, writes tar-split entries to packer p,
// and ensures the pipe writer is closed (with error if needed). If done != nil,
// it will send exactly one error value (nil on success) when fully complete
// (including padding draining).
func runInputTarStream(outputRdr io.Reader, pW *io.PipeWriter, p storage.Packer, fp storage.FilePutter, done chan<- error) {
	// Ensure the consumer eventually sees EOF (or an error).
	defer pW.Close()

	fail := func(err error) {
		pW.CloseWithError(err)
		if done != nil {
			done <- err
		}
	}

	tr := tar.NewReader(outputRdr)
	tr.RawAccounting = true

	for {
		hdr, err := tr.Next()
		if err != nil {
			if err != io.EOF {
				fail(err)
				return
			}
			// even when an EOF is reached, there is often 1024 null bytes on
			// the end of an archive. Collect them too.
			if b := tr.RawBytes(); len(b) > 0 {
				if _, err := p.AddEntry(storage.Entry{
					Type:    storage.SegmentType,
					Payload: b,
				}); err != nil {
					fail(err)
					return
				}
			}
			break // not return. We need the end of the reader.
		}
		if hdr == nil {
			break // not return. We need the end of the reader.
		}

		if b := tr.RawBytes(); len(b) > 0 {
			if _, err := p.AddEntry(storage.Entry{
				Type:    storage.SegmentType,
				Payload: b,
			}); err != nil {
				fail(err)
				return
			}
		}

		var csum []byte
		if hdr.Size > 0 {
			_, csum, err = fp.Put(hdr.Name, tr)
			if err != nil {
				fail(err)
				return
			}
		}

		entry := storage.Entry{
			Type:    storage.FileType,
			Size:    hdr.Size,
			Payload: csum,
		}
		// For proper marshalling of non-utf8 characters
		entry.SetName(hdr.Name)

		// File entries added, regardless of size
		if _, err := p.AddEntry(entry); err != nil {
			fail(err)
			return
		}

		if b := tr.RawBytes(); len(b) > 0 {
			if _, err := p.AddEntry(storage.Entry{
				Type:    storage.SegmentType,
				Payload: b,
			}); err != nil {
				fail(err)
				return
			}
		}
	}

	// It is allowable, and not uncommon that there is further padding on
	// the end of an archive, apart from the expected 1024 null bytes. We
	// do this in chunks rather than in one go to avoid cases where a
	// maliciously crafted tar file tries to trick us into reading many GBs
	// into memory.
	const paddingChunkSize = 1024 * 1024
	var paddingChunk [paddingChunkSize]byte
	for {
		n, err := outputRdr.Read(paddingChunk[:])
		if n != 0 {
			if _, aerr := p.AddEntry(storage.Entry{
				Type:    storage.SegmentType,
				Payload: paddingChunk[:n],
			}); aerr != nil {
				fail(aerr)
				return
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			fail(err)
			return
		}
	}

	if done != nil {
		done <- nil
	}
}

// newInputTarStreamCommon contains the shared setup logic.
// If bestEffort is true, the pipe writer is wrapped so the tar-split goroutine
// can keep parsing to completion even if the consumer closes early.
func newInputTarStreamCommon(
	r io.Reader,
	p storage.Packer,
	fp storage.FilePutter,
	bestEffort bool,
	withDone bool,
) (pr *io.PipeReader, pw *io.PipeWriter, outputRdr io.Reader, done <-chan error) {
	pr, pw = io.Pipe()

	// we need a putter that will generate the crc64 sums of file payloads
	if fp == nil {
		fp = storage.NewDiscardFilePutter()
	}

	if withDone {
		ch := make(chan error, 1)
		done = ch
		if bestEffort {
			bew := &bestEffortPipeWriter{pw: pw}
			outputRdr = io.TeeReader(r, bew)
		} else {
			outputRdr = io.TeeReader(r, pw)
		}
		go runInputTarStream(outputRdr, pw, p, fp, ch)
		return pr, pw, outputRdr, done
	}

	// No done channel.
	if bestEffort {
		bew := &bestEffortPipeWriter{pw: pw}
		outputRdr = io.TeeReader(r, bew)
	} else {
		outputRdr = io.TeeReader(r, pw)
	}
	go runInputTarStream(outputRdr, pw, p, fp, nil)
	return pr, pw, outputRdr, nil
}

// NewInputTarStream wraps the Reader stream of a tar archive and provides a
// Reader stream of the same.
//
// In the middle it will pack the segments and file metadata to storage.Packer `p`.
//
// The storage.FilePutter is where payload of files in the stream are stashed.
// If this stashing is not needed, you can provide a nil storage.FilePutter.
// Since the checksumming is still needed, a default of NewDiscardFilePutter
// will be used internally.
func NewInputTarStream(r io.Reader, p storage.Packer, fp storage.FilePutter) (io.Reader, error) {
	pr, _, _, _ := newInputTarStreamCommon(r, p, fp, false, false)
	return pr, nil
}

// NewInputTarStreamWithDone wraps the Reader stream of a tar archive and provides a
// Reader stream of the same.
//
// In the middle it will pack the segments and file metadata to storage.Packer `p`.
//
// It also returns a done channel that will receive exactly one error value
// (nil on success) when the internal goroutine has fully completed parsing
// the tar stream (including the final paddingChunk draining loop) and has
// finished writing all entries to `p`.
//
// The returned reader is an io.ReadCloser so callers can stop early; closing
// it will stop delivering bytes to the caller, while allowing the internal
// goroutine to continue reading `r` and completing metadata packing.
func NewInputTarStreamWithDone(r io.Reader, p storage.Packer, fp storage.FilePutter) (io.ReadCloser, <-chan error, error) {
	pr, _, _, done := newInputTarStreamCommon(r, p, fp, true, true)
	return pr, done, nil
}
