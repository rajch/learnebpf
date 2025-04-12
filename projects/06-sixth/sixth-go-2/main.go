package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

func intSliceToString(input []int8) string {
	slice := input
	bytes := make([]byte, len(slice))
	for i, v := range slice {
		bytes[i] = byte(v)
	}

	return unix.ByteSliceToString(bytes)
}

func main() {
	var objs sixthObjects

	fmt.Println("Loading BPF Program...")
	err := loadSixthObjects(&objs, nil)
	if err != nil {
		log.Fatalf("Error loading BPF program: %v", err)
	}

	defer objs.Close()

	fmt.Println("BPF program loaded. Now attaching uprobe...")
	sharedlib := "/usr/lib/libreadline.so.8"
	ex, err := link.OpenExecutable(sharedlib)
	if err != nil {
		log.Fatalf("Error finding shared library '%v': %v", sharedlib, err)
	}

	up, err := ex.Uprobe("readline", objs.Sixth, nil)
	if err != nil {
		log.Fatalf("Error attaching uprobe: %v", err)
	}

	defer up.Close()

	fmt.Println("uprobe attached. Now setting up ringbuffer...")
	rdr, err := ringbuf.NewReader(objs.Buffer)
	if err != nil {
		log.Fatalf("Error setting up ringbuffer: %v", err)
	}

	defer rdr.Close()

	fmt.Println("Ringbuffer set. Now setting up monitoring...")

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stopper

		err := rdr.Close()
		if err != nil {
			log.Fatalf("Error while stopping userspace program: %v", err)
		}
	}()

	fmt.Println("Monitoring started. Press ^C to stop...")

	record := &ringbuf.Record{}
	data := sixthSixthData{}

	for {
		err := rdr.ReadInto(record)
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		// Parse the ringbuf event entry into a sixthSixthData structure.
		err = binary.Read(bytes.NewBuffer(record.RawSample), hostEndian, &data)
		if err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}

		log.Printf("Readline called with: %s\n", intSliceToString(data.ReadlinePrompt[:]))
	}
}
