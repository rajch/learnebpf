package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

func main() {
	var objs thirdObjects

	err := loadThirdObjects(&objs, nil)
	if err != nil {
		log.Fatalf("Could not load BPF objects: %v.\n", err)
	}

	defer objs.Close()

	kp, err := link.Kprobe("sys_execve", objs.thirdPrograms.Third, nil)
	if err != nil {
		log.Fatalf("Could not load attach to kprobe: %v.\n", err)
	}

	defer kp.Close()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT)
	signal.Notify(stop, syscall.SIGTERM)

	tick := time.Tick(time.Second * 5)

	fmt.Println("Press Ctrl+C to stop...")
	for {
		select {
		case <-tick:
			var key string
			var value thirdCounterRecordT

			iter := objs.thirdMaps.CounterMap.Iterate()
			for iter.Next(&key, &value) {
				slice := value.ProgramName[:]
				bytes := make([]byte, len(slice))
				for i, v := range slice {
					bytes[i] = byte(v)
				}

				pname := unix.ByteSliceToString(bytes)

				fmt.Printf("%v was executed %v times.\n", pname, value.Counter)
			}

			fmt.Println("=============================================")
		case <-stop:
			log.Print("Received signal, exiting..")
			return
		}
	}
}
