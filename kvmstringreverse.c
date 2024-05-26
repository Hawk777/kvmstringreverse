#include <fcntl.h>
#include <inttypes.h>
#include <linux/kvm.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static const size_t guestBSSSize = 65536;

static const char *formatVector(uint8_t vector) {
	// Volume 3 section 6.3.1
	static const char VECTORS[][4] = {
		[0] = "#DE",
		[1] = "#DB",
		[2] = "NMI",
		[3] = "#BP",
		[4] = "#OF",
		[5] = "#BR",
		[6] = "#UD",
		[7] = "#NM",
		[8] = "#DF",
		[9] = "CSO",
		[10] = "#TS",
		[11] = "#NP",
		[12] = "#SS",
		[13] = "#GP",
		[14] = "#PF",
		[15] = "RSV",
		[16] = "#MF",
		[17] = "#AC",
		[18] = "#MC",
		[19] = "#XM",
		[20] = "#VE",
		[21] = "#CP",
		[22] = "RSV",
		[23] = "RSV",
		[24] = "RSV",
		[25] = "RSV",
		[26] = "RSV",
		[27] = "RSV",
		[28] = "RSV",
		[29] = "RSV",
		[30] = "RSV",
		[31] = "RSV",
	};
	if(vector < sizeof(VECTORS) / sizeof(*VECTORS)) {
		return VECTORS[vector];
	} else {
		return "HWINT";
	}
}

static const char *formatExitReason(uint32_t reason) {
	static const char * const REASONS[] = {
		[KVM_EXIT_UNKNOWN] = "KVM_EXIT_UNKNOWN",
		[KVM_EXIT_EXCEPTION] = "KVM_EXIT_EXCEPTION",
		[KVM_EXIT_IO] = "KVM_EXIT_IO",
		[KVM_EXIT_HYPERCALL] = "KVM_EXIT_HYPERCALL",
		[KVM_EXIT_DEBUG] = "KVM_EXIT_DEBUG",
		[KVM_EXIT_HLT] = "KVM_EXIT_HLT",
		[KVM_EXIT_MMIO] = "KVM_EXIT_MMIO",
		[KVM_EXIT_IRQ_WINDOW_OPEN] = "KVM_EXIT_IRQ_WINDOW_OPEN",
		[KVM_EXIT_SHUTDOWN] = "KVM_EXIT_SHUTDOWN",
		[KVM_EXIT_FAIL_ENTRY] = "KVM_EXIT_FAIL_ENTRY",
		[KVM_EXIT_INTR] = "KVM_EXIT_INTR",
		[KVM_EXIT_SET_TPR] = "KVM_EXIT_SET_TPR",
		[KVM_EXIT_TPR_ACCESS] = "KVM_EXIT_TPR_ACCESS",
		[KVM_EXIT_S390_SIEIC] = "KVM_EXIT_S390_SIEIC",
		[KVM_EXIT_S390_RESET] = "KVM_EXIT_S390_RESET",
		[KVM_EXIT_DCR] = "KVM_EXIT_DCR",
		[KVM_EXIT_NMI] = "KVM_EXIT_NMI",
		[KVM_EXIT_INTERNAL_ERROR] = "KVM_EXIT_INTERNAL_ERROR",
		[KVM_EXIT_OSI] = "KVM_EXIT_OSI",
		[KVM_EXIT_PAPR_HCALL	] = "KVM_EXIT_PAPR_HCALL	",
		[KVM_EXIT_S390_UCONTROL	] = "KVM_EXIT_S390_UCONTROL	",
		[KVM_EXIT_WATCHDOG] = "KVM_EXIT_WATCHDOG",
		[KVM_EXIT_S390_TSCH] = "KVM_EXIT_S390_TSCH",
		[KVM_EXIT_EPR] = "KVM_EXIT_EPR",
		[KVM_EXIT_SYSTEM_EVENT] = "KVM_EXIT_SYSTEM_EVENT",
		[KVM_EXIT_S390_STSI] = "KVM_EXIT_S390_STSI",
		[KVM_EXIT_IOAPIC_EOI] = "KVM_EXIT_IOAPIC_EOI",
		[KVM_EXIT_HYPERV] = "KVM_EXIT_HYPERV",
		[KVM_EXIT_ARM_NISV] = "KVM_EXIT_ARM_NISV",
		[KVM_EXIT_X86_RDMSR] = "KVM_EXIT_X86_RDMSR",
		[KVM_EXIT_X86_WRMSR] = "KVM_EXIT_X86_WRMSR",
		[KVM_EXIT_DIRTY_RING_FULL] = "KVM_EXIT_DIRTY_RING_FULL",
		[KVM_EXIT_AP_RESET_HOLD] = "KVM_EXIT_AP_RESET_HOLD",
		[KVM_EXIT_X86_BUS_LOCK] = "KVM_EXIT_X86_BUS_LOCK",
		[KVM_EXIT_XEN] = "KVM_EXIT_XEN",
		[KVM_EXIT_RISCV_SBI] = "KVM_EXIT_RISCV_SBI",
		[KVM_EXIT_RISCV_CSR] = "KVM_EXIT_RISCV_CSR",
		[KVM_EXIT_NOTIFY] = "KVM_EXIT_NOTIFY",
	};
	if(reason < sizeof(REASONS) / sizeof(*REASONS) && REASONS[reason]) {
		return REASONS[reason];
	} else {
		return "<invalid reason code>";
	}
}

static const char *formatBasicExitReason(uint16_t basic) {
	// Volume 3 appendix C
	static const char * const REASONS[] = {
		[33] = "VM-entry failure due to invalid guest state",
		[49] = "EPT misconfiguration",
	};
	if(basic < sizeof(REASONS) / sizeof(*REASONS) && REASONS[basic]) {
		return REASONS[basic];
	} else {
		return "Unknown";
	}
}

static void printVMXExitReason(uint64_t exitReasonFull, FILE *fp) {
	fprintf(fp, "Exit reason:        0x%016" PRIX64 "\n", exitReasonFull);
	uint16_t exitReasonBasic = (uint16_t) exitReasonFull;
	fprintf(fp, "  Basic:            %" PRIu16 " (%s)\n", exitReasonBasic, formatBasicExitReason(exitReasonBasic));
	fprintf(fp, "  Busy shadow stack:%u\n", (unsigned int) ((exitReasonFull >> 25) & 1));
	fprintf(fp, "  Bus lock:         %u\n", (unsigned int) ((exitReasonFull >> 26) & 1));
	fprintf(fp, "  Enclave mode:     %u\n", (unsigned int) ((exitReasonFull >> 27) & 1));
	fprintf(fp, "  SMI pending MTF:  %u\n", (unsigned int) ((exitReasonFull >> 28) & 1));
	fprintf(fp, "  SMI from root:    %u\n", (unsigned int) ((exitReasonFull >> 29) & 1));
	fprintf(fp, "  Failed VM entry:  %u\n", (unsigned int) ((exitReasonFull >> 31) & 1));
}

static void printInternalError(const struct kvm_run *runControl, FILE *fp) {
	uint32_t subError = runControl->internal.suberror;
	static const char * const ERRORS[] = {
		[KVM_INTERNAL_ERROR_EMULATION] = "KVM_INTERNAL_ERROR_EMULATION",
		[KVM_INTERNAL_ERROR_SIMUL_EX] = "KVM_INTERNAL_ERROR_SIMUL_EX",
		[KVM_INTERNAL_ERROR_DELIVERY_EV] = "KVM_INTERNAL_ERROR_DELIVERY_EV",
		[KVM_INTERNAL_ERROR_UNEXPECTED_EXIT_REASON] = "KVM_INTERNAL_ERROR_UNEXPECTED_EXIT_REASON",
	};
	if(subError < sizeof(ERRORS) / sizeof(*ERRORS) && ERRORS[subError]) {
		fprintf(fp, "Internal error of type %s\n", ERRORS[subError]);
	} else {
		fputs("Internal error of unknown type\n", fp);
		return;
	}

	uint32_t ndata = runControl->internal.ndata;
	const uint64_t *data = (const uint64_t *) runControl->internal.data;
	if(subError == KVM_INTERNAL_ERROR_DELIVERY_EV && (ndata == 4 || ndata == 5)) {
		static const char *VECTORING_TYPES[] = {
			"External interrupt",
			"Not used",
			"NMI",
			"Hardware exception",
			"Not used",
			"Privileged software exception",
			"Software exception",
			"Not used",
		};

		uint64_t vectoringInfo = data[0];
		uint64_t exitReasonFull = data[1];
		uint64_t exitQualification = data[2];
		uint64_t guestPhysical;
		uint64_t lastVMEntryCPU;
		bool hasGuestPhysical;
		if(runControl->internal.ndata == 5) {
			guestPhysical = data[3];
			lastVMEntryCPU = data[4];
			hasGuestPhysical = true;
		} else {
			lastVMEntryCPU = data[3];
			hasGuestPhysical = false;
		}

		fprintf(fp, "Vectoring info:     0x%016" PRIX64 "\n", vectoringInfo);
		uint8_t vector = (uint8_t) vectoringInfo;
		fprintf(fp, "  Vector:           %" PRIu8 " (%s)\n", vector, formatVector(vector));
		unsigned int vectoringType = (vectoringInfo >> 8) & 7;
		fprintf(fp, "  Type:             %u (%s)\n", vectoringType, VECTORING_TYPES[vectoringType]);
		fprintf(fp, "  Error code valid: %u\n", (unsigned int) ((vectoringInfo >> 11) & 1));
		fprintf(fp, "  NMI unblock IRET: %u\n", (unsigned int) ((vectoringInfo >> 12) & 1));
		fprintf(fp, "  Valid:            %u\n", (unsigned int) ((vectoringInfo >> 31) & 1));
		printVMXExitReason(exitReasonFull, fp);
		fprintf(fp, "Exit qualification: 0x%016" PRIX64 "\n", exitQualification);
		if(hasGuestPhysical) {
			fprintf(fp, "Guest physical:     0x%016" PRIX64 "\n", guestPhysical);
		}
		fprintf(fp, "Last VM entry CPU:  0x%016" PRIX64 "\n", lastVMEntryCPU);
	} else {
		for(uint32_t i = 0; i != ndata; ++i) {
			fprintf(fp, "data[%" PRIu32 "] = 0x%016" PRIX64 "\n", i, data[i]);
		}
	}
}

static void printFailEntry(const struct kvm_run *run, FILE *fp) {
	printVMXExitReason(run->fail_entry.hardware_entry_failure_reason, fp);
	fprintf(stderr, "CPU: %" PRIu32 "\n", (uint32_t) run->fail_entry.cpu);
}

static void printRegs(const struct kvm_regs *regs, FILE *fp) {
	fputs("=== REGS ===\n", fp);
	fprintf(fp, "RAX = 0x%016" PRIX64 "\n", (uint64_t) regs->rax);
	fprintf(fp, "RBX = 0x%016" PRIX64 "\n", (uint64_t) regs->rbx);
	fprintf(fp, "RCX = 0x%016" PRIX64 "\n", (uint64_t) regs->rcx);
	fprintf(fp, "RDX = 0x%016" PRIX64 "\n", (uint64_t) regs->rdx);
	fprintf(fp, "RSI = 0x%016" PRIX64 "\n", (uint64_t) regs->rsi);
	fprintf(fp, "RDI = 0x%016" PRIX64 "\n", (uint64_t) regs->rdi);
	fprintf(fp, "RSP = 0x%016" PRIX64 "\n", (uint64_t) regs->rsp);
	fprintf(fp, "RBP = 0x%016" PRIX64 "\n", (uint64_t) regs->rbp);
	fprintf(fp, "R8  = 0x%016" PRIX64 "\n", (uint64_t) regs->r8);
	fprintf(fp, "R9  = 0x%016" PRIX64 "\n", (uint64_t) regs->r9);
	fprintf(fp, "R10 = 0x%016" PRIX64 "\n", (uint64_t) regs->r10);
	fprintf(fp, "R11 = 0x%016" PRIX64 "\n", (uint64_t) regs->r11);
	fprintf(fp, "R12 = 0x%016" PRIX64 "\n", (uint64_t) regs->r12);
	fprintf(fp, "R13 = 0x%016" PRIX64 "\n", (uint64_t) regs->r13);
	fprintf(fp, "R14 = 0x%016" PRIX64 "\n", (uint64_t) regs->r14);
	fprintf(fp, "R15 = 0x%016" PRIX64 "\n", (uint64_t) regs->r15);
	fprintf(fp, "RIP = 0x%016" PRIX64 "\n", (uint64_t) regs->rip);
	fprintf(fp, "RFL = 0x%016" PRIX64 "\n", (uint64_t) regs->rflags);
}

static void printRegsFD(int vcpu, FILE *fp) {
	struct kvm_regs regs;
	if(ioctl(vcpu, KVM_GET_REGS, &regs) >= 0) {
		printRegs(&regs, fp);
	}
}

static void printSegment(const char *name, const struct kvm_segment *seg, FILE *fp) {
	fprintf(fp,
		"%s: { "
		"base = 0x%" PRIX64 ", "
		"limit=0x%" PRIX32 ", "
		"selector=%" PRIu16 ", "
		"type=%" PRIu8 ", "
		"present=%" PRIu8 ", "
		"DPL=%" PRIu8 ", "
		"DB=%" PRIu8 ", "
		"S=%" PRIu8 ", "
		"L=%" PRIu8 ", "
		"G=%" PRIu8 ", "
		"unusable=%" PRIu8
		" }\n",
		name,
		(uint64_t) seg->base,
		(uint32_t) seg->limit,
		(uint16_t) seg->selector,
		(uint8_t) seg->type,
		(uint8_t) seg->present,
		(uint8_t) seg->dpl,
		(uint8_t) seg->db,
		(uint8_t) seg->s,
		(uint8_t) seg->l,
		(uint8_t) seg->g,
		(uint8_t) seg->unusable);
}

static void printDTable(const char *name, const struct kvm_dtable *dtable, FILE *fp) {
	fprintf(fp, "%s: { "
		"base = 0x%" PRIX64 ", "
		"limit=0x%" PRIX16
		" }\n",
		name,
		(uint64_t) dtable->base,
		(uint16_t) dtable->limit);
}

static void printSRegs(const struct kvm_sregs *regs, FILE *fp) {
	fputs("=== SREGS ===\n", fp);
	printSegment("CS", &regs->cs, fp);
	printSegment("DS", &regs->ds, fp);
	printSegment("ES", &regs->es, fp);
	printSegment("FS", &regs->fs, fp);
	printSegment("GS", &regs->gs, fp);
	printSegment("SS", &regs->ss, fp);
	printSegment("TR", &regs->tr, fp);
	printSegment("LDT", &regs->ldt, fp);
	printDTable("GDT", &regs->gdt, fp);
	printDTable("IDT", &regs->idt, fp);
	fprintf(fp, "CR0:  0x%016" PRIX64 "\n", (uint64_t) regs->cr0);
	fprintf(fp, "CR2:  0x%016" PRIX64 "\n", (uint64_t) regs->cr2);
	fprintf(fp, "CR3:  0x%016" PRIX64 "\n", (uint64_t) regs->cr3);
	fprintf(fp, "CR4:  0x%016" PRIX64 "\n", (uint64_t) regs->cr4);
	fprintf(fp, "CR8:  0x%016" PRIX64 "\n", (uint64_t) regs->cr8);
	fprintf(fp, "EFER: 0x%016" PRIX64 "\n", (uint64_t) regs->efer);
	fprintf(fp, "APIC: 0x%016" PRIX64 "\n", (uint64_t) regs->apic_base);
}

static void printSRegsFD(int vcpu, FILE *fp) {
	struct kvm_sregs regs;
	if(ioctl(vcpu, KVM_GET_SREGS, &regs) >= 0) {
		printSRegs(&regs, fp);
	}
}

static void printVCPU(int vcpu, FILE *fp) {
	printRegsFD(vcpu, fp);
	printSRegsFD(vcpu, fp);
}

static void printExitShort(const struct kvm_run *run, FILE *fp) {
	fprintf(fp, "VMEXIT for reason %s\n", formatExitReason(run->exit_reason));
}

static void printExit(const struct kvm_run *run, int vcpu, FILE *fp) {
	printExitShort(run, fp);
	switch(run->exit_reason) {
		case KVM_EXIT_FAIL_ENTRY:
			printFailEntry(run, stderr);
			break;

		case KVM_EXIT_INTERNAL_ERROR:
			printInternalError(run, stderr);
			break;
	}
	printVCPU(vcpu, stderr);
}

int main(void) {
	long pageSize = sysconf(_SC_PAGE_SIZE);
	if(pageSize < 0) { perror("sysconf(_SC_PAGE_SIZE)"); return 1; }

	int guestFD = open("guest", O_RDONLY);
	if(guestFD < 0) { perror("open(guest)"); return 1; }

	size_t guestTextSize;
	{
		struct stat guestStat;
		if(fstat(guestFD, &guestStat) < 0) { perror("stat(guest)"); return 1; }
		guestTextSize = (guestStat.st_size + pageSize - 1) / pageSize * pageSize;
	}

	const void *guestText = mmap(nullptr, guestTextSize, PROT_READ, MAP_SHARED, guestFD, 0);
	if(guestText == MAP_FAILED) { perror("mmap(guest)"); return 1; }

	if(close(guestFD) < 0) { perror("close(guest)"); return 1; }
	guestFD = -1;

	void *guestBSS = mmap(nullptr, guestBSSSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	if(guestBSS == MAP_FAILED) { perror("mmap(bss)"); return 1; }

	int sysFD = open("/dev/kvm", O_RDWR);
	if(sysFD < 0) { perror("open(/dev/kvm)"); return 1; }

	int apiVersion = ioctl(sysFD, KVM_GET_API_VERSION, 0);
	if(apiVersion < 0) { perror("KVM_GET_API_VERSION"); return 1; }
	if(apiVersion != 12) { fprintf(stderr, "KVM API version %d not supported\n", apiVersion); return 1; }

	int vcpuMMapSize = ioctl(sysFD, KVM_GET_VCPU_MMAP_SIZE, 0);
	if(vcpuMMapSize < 0) { perror("KVM_GET_VCPU_MMAP_SIZE"); return 1; }

	int canCheckCapsOnVM = ioctl(sysFD, KVM_CHECK_EXTENSION, KVM_CAP_CHECK_EXTENSION_VM);
	if(canCheckCapsOnVM < 0) { perror("KVM_CHECK_EXTENSION(KVM_CAP_CHECK_EXTENSION_VM)"); return 1; }
	if(!canCheckCapsOnVM) { fputs("KVM_CHECK_EXTENSION(KVM_CAP_CHECK_EXTENSION_VM): not supported\n", stderr); return 1; }

	int vmFD = ioctl(sysFD, KVM_CREATE_VM, 0);
	if(vmFD < 0) { perror("KVM_CREATE_VM"); return 1; }

	int maxVCPUs = ioctl(vmFD, KVM_CHECK_EXTENSION, KVM_CAP_MAX_VCPUS);
	if(maxVCPUs < 0) { perror("KVM_CHECK_EXTENSION(KVM_CAP_MAX_VCPUS)"); return 1; }
	if(!maxVCPUs) { fputs("KVM_CHECK_EXTENSION(KVM_CAP_MAX_VCPUS): not supported\n", stderr); return 1; }

	int maxMemSlots = ioctl(vmFD, KVM_CHECK_EXTENSION, KVM_CAP_NR_MEMSLOTS);
	if(maxMemSlots < 0) { perror("KVM_CHECK_EXTENSION(KVM_CAP_NR_MEMSLOTS)"); return 1; }
	if(!maxMemSlots) { fputs("KVM_CHECK_EXTENSION(KVM_CAP_NR_MEMSLOTS): not supported\n", stderr); return 1; }
	if(maxMemSlots < 2) { fputs("Not enough memslots\n", stderr); return 1; }

	int readonlyMemorySupported = ioctl(vmFD, KVM_CHECK_EXTENSION, KVM_CAP_READONLY_MEM);
	if(readonlyMemorySupported < 0) { perror("KVM_CHECK_EXTENSION(KVM_CAP_READONLY_MEM)"); return 1; }
	if(!readonlyMemorySupported) { fputs("KVM_CHECK_EXTENSION(KVM_CAP_READONLY_MEM): not supported\n", stderr); return 1; }

	int internalErrorDataSupported = ioctl(vmFD, KVM_CHECK_EXTENSION, KVM_CAP_INTERNAL_ERROR_DATA);
	if(internalErrorDataSupported < 0) { perror("KVM_CHECK_EXTENSION(KVM_CAP_INTERNAL_ERROR_DATA)"); return 1; }
	if(!internalErrorDataSupported) { fputs("KVM_CHECK_EXTENSION(KVM_CAP_INTERNAL_ERROR_DATA): not supported\n", stderr); return 1; }

	int canSetMaxVCPUID = ioctl(vmFD, KVM_CHECK_EXTENSION, KVM_CAP_MAX_VCPU_ID);
	if(canSetMaxVCPUID < 0) { perror("KVM_CHECK_EXTENSION(KVM_CAP_MAX_VPCU_ID)"); return 1; }
	if(canSetMaxVCPUID) {
		struct kvm_enable_cap cap;
		memset(&cap, 0, sizeof(cap));
		cap.cap = KVM_CAP_MAX_VCPU_ID;
		cap.args[0] = 0;
		if(ioctl(vmFD, KVM_ENABLE_CAP, &cap) < 0) { perror("KVM_ENABLE_CAP(KVM_CAP_MAX_VCPU_ID)"); return 1; }
	}

	int vcpuFD = ioctl(vmFD, KVM_CREATE_VCPU, 0);
	if(vcpuFD < 0) { perror("KVM_CREATE_VCPU"); return 1; }

	{
		struct kvm_userspace_memory_region region = {
			.slot = 0,
			.flags = KVM_MEM_READONLY,
			.guest_phys_addr = 0x10000000,
			.memory_size = guestTextSize,
			.userspace_addr = (uint64_t) guestText,
		};
		if(ioctl(vmFD, KVM_SET_USER_MEMORY_REGION, &region) < 0) { perror("KVM_SET_USER_MEMORY_REGION(.text)"); return 1; }
	}

	{
		struct kvm_userspace_memory_region region = {
			.slot = 1,
			.flags = 0,
			.guest_phys_addr = 0x20000000,
			.memory_size = guestBSSSize,
			.userspace_addr = (uint64_t) guestBSS,
		};
		if(ioctl(vmFD, KVM_SET_USER_MEMORY_REGION, &region) < 0) { perror("KVM_SET_USER_MEMORY_REGION(.bss)"); return 1; }
	}

	if(ioctl(vmFD, KVM_SET_TSS_ADDR, 0x30000000) < 0) { perror("KVM_SET_TSS_ADDR"); return 1; }

	{
		struct kvm_sregs regs = {
			.cs = {
				.base = 0,
				.limit = 0xFFFFFFFF,
				.selector = 8,
				.type = 11, // execute/read code segment, accessed
				.present = 1,
				.dpl = 0,
				.db = 1, // 32-bit (not 16-bit)
				.s = 1, // non-system segment
				.l = 0, // 32-bit (not 64-bit)
				.g = 1, // limit is in pages
			},
			.ds = {
				.base = 0,
				.limit = 0xFFFFFFFF,
				.selector = 16,
				.type = 3, // read/write data segment, accessed
				.present = 1,
				.dpl = 0,
				.db = 1, // 32-bit (ignored)
				.s = 1, // non-system segment
				.l = 0, // 32-bit (not 64-bit) (ignored)
				.g = 1, // limit is in pages
			},
			.es = {
				.base = 0,
				.limit = 0xFFFFFFFF,
				.selector = 16,
				.type = 3, // read/write data segment, accessed
				.present = 1,
				.dpl = 0,
				.db = 1, // 32-bit (ignored)
				.s = 1, // non-system segment
				.l = 0, // 32-bit (not 64-bit) (ignored)
				.g = 1, // limit is in pages
			},
			.fs = {
				.base = 0,
				.limit = 0xFFFFFFFF,
				.selector = 16,
				.type = 3, // read/write data segment, accessed
				.present = 1,
				.dpl = 0,
				.db = 1, // 32-bit (ignored)
				.s = 1, // non-system segment
				.l = 0, // 32-bit (not 64-bit) (ignored)
				.g = 1, // limit is in pages
			},
			.gs = {
				.base = 0,
				.limit = 0xFFFFFFFF,
				.selector = 16,
				.type = 3, // read/write data segment, accessed
				.present = 1,
				.dpl = 0,
				.db = 1, // 32-bit (ignored)
				.s = 1, // non-system segment
				.l = 0, // 32-bit (not 64-bit) (ignored)
				.g = 1, // limit is in pages
			},
			.ss = {
				.base = 0,
				.limit = 0xFFFFFFFF,
				.selector = 16,
				.type = 3, // read/write data segment, accessed
				.present = 1,
				.dpl = 0,
				.db = 1, // 32-bit (ignored)
				.s = 1, // non-system segment
				.l = 0, // 32-bit (not 64-bit) (ignored)
				.g = 1, // limit is in pages
			},
			.tr = {
				.base = 0,
				.limit = 0,
				.selector = 0,
				.type = 11, // 32-bit busy TSS
				.present = 1,
				.dpl = 0,
				.db = 0,
				.s = 0, // system segment
				.l = 0,
				.g = 0,
			},
			.ldt = { .unusable = 1 },
			.gdt = {
				.base = 0,
				.limit = 0,
			},
			.idt = {
				.base = 0,
				.limit = 0,
			},
			.cr0 =
				(1 << 16) // WP
				| (1 << 5) // NE
				| (1 << 0), // PE
			.cr2 = 0,
			.cr3 = 0x03000000,
			.cr4 =
				(1 << 3), // DE
			.cr8 = 0,
			.efer = 0,
			.apic_base = 0x04000000,
			.interrupt_bitmap = {},
		};
		if(ioctl(vcpuFD, KVM_SET_SREGS, &regs) < 0) { perror("KVM_SET_REGS"); return 1; }
	}

	{
		struct kvm_regs regs = {
			.rip = 0x10000000,
		};
		if(ioctl(vcpuFD, KVM_SET_REGS, &regs) < 0) { perror("KVM_SET_REGS"); return 1; }
	}

	struct kvm_run *runControl = mmap(0, vcpuMMapSize, PROT_READ | PROT_WRITE, MAP_SHARED, vcpuFD, 0);
	if(runControl == MAP_FAILED) { perror("mmap(vcpu)"); return 1; }

	for(;;) {
		if(ioctl(vcpuFD, KVM_RUN, 0) < 0) { perror("KVM_RUN"); return 1; }
		if(runControl->exit_reason == KVM_EXIT_IO) {
			if(runControl->io.count != 1) {
				fputs("Non-byte port accesses not supported\n", stderr);
				return 1;
			}
			switch(runControl->io.direction) {
				case KVM_EXIT_IO_IN:
					if(runControl->io.port != 42) {
						fprintf(stderr, "Incorrect I/O port %" PRIu16 " read, only port 42 supported\n", (uint16_t) runControl->io.port);
						return 1;
					}
					int ch = getchar();
					char asChar = (ch == EOF) ? 0 : ((char) ch);
					memcpy(((char *) runControl) + runControl->io.data_offset, &asChar, 1);
					break;

				case KVM_EXIT_IO_OUT:
					if(runControl->io.port != 47) {
						fprintf(stderr, "Incorrect I/O port %" PRIu16 " written, only port 47 supported\n", (uint16_t) runControl->io.port);
						return 1;
					}
					char written;
					memcpy(&written, ((const char *) runControl) + runControl->io.data_offset, 1);
					putchar(written);
					break;

				default:
					fprintf(stderr, "KVM_EXIT_IO with impossible direction %" PRIu8 "\n", (uint8_t) runControl->io.direction);
					return 1;
			}
		} else if(runControl->exit_reason == KVM_EXIT_HLT) {
			putchar('\n');
			break;
		} else {
			printExit(runControl, vcpuFD, stderr);
			return 1;
		}
	}

	return 0;
}
