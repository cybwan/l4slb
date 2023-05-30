package topology

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"runtime"
	"strconv"
)

const (
	TOPOLOGY_DIR   string = "/sys/devices/system/cpu/cpu"
	NUMA_NODE_FILE string = "/topology/physical_package_id"
)

type CpuTopology struct {
	Cpu2Numa map[int]int
	Numa2Cpu map[int][]int
	Ncpus    int
}

func getNumaNodeOfCpu(i int) int {
	fileName := TOPOLOGY_DIR + strconv.Itoa(i) + NUMA_NODE_FILE
	numa_bytes, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.Fatal("cannot parse numa node id for file ", i, err)
	}
	numa_slice := bytes.Split(numa_bytes, []byte{'\n'})
	if len(numa_slice) < 1 {
		log.Fatal("invalid numa file format ", string(numa_bytes))
	}
	numa, err := strconv.Atoi(string(numa_slice[0]))
	if err != nil {
		log.Fatal("cannot converit numa id to int ", err)
	}
	return numa
}

func (topo *CpuTopology) GetNumaListForCpus(cpus []int) []int {
	var numa_nodes []int
	for _, cpu := range cpus {
		if node, exists := topo.Cpu2Numa[cpu]; exists {
			numa_nodes = append(numa_nodes, node)
		} else {
			log.Fatal("cant find numa mapping for cpu: ", cpu)
		}
	}
	return numa_nodes
}

func GetCpuTopology() CpuTopology {
	ncpus := runtime.NumCPU()
	fmt.Println("number of CPUs ", ncpus)
	var topology CpuTopology
	topology.Cpu2Numa = make(map[int]int)
	topology.Numa2Cpu = make(map[int][]int)
	topology.Ncpus = ncpus
	for i := 0; i < ncpus; i++ {
		numa := getNumaNodeOfCpu(i)
		topology.Cpu2Numa[i] = numa
		topology.Numa2Cpu[numa] = append(topology.Numa2Cpu[numa], i)
	}
	return topology
}
