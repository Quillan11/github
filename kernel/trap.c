#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"

struct spinlock tickslock;
uint ticks;

extern char trampoline[], uservec[], userret[];

// in kernelvec.S, calls kerneltrap().
void kernelvec();

extern int devintr();
extern void switchtrapframe(struct trapframe * origin, struct trapframe * handler);//added by myself

void
trapinit(void)
{
  initlock(&tickslock, "time");
}

// set up to take exceptions and traps while in the kernel.
void
trapinithart(void)
{
  w_stvec((uint64)kernelvec);
}

//
// handle an interrupt, exception, or system call from user space.
// called from trampoline.S
//
// 译：处理一个从用户空间来的中断、异常、或系统调用
void
usertrap(void)
{
  // 用于接收处理设备中断返回值的变量
  // 对应的细节我们到设备中断与驱动章节再仔细研究
  int which_dev = 0;

    // 读取sstatus寄存器，判断是否来自user mode
  // 如果不是，则陷入panic
  if((r_sstatus() & SSTATUS_SPP) != 0)
    panic("usertrap: not from user mode");

  // send interrupts and exceptions to kerneltrap(),
  // since we're now in the kernel.
    // 译：将当前模式下的中断和异常处理全部发送到kernelvec函数
  // 因为我们当前处于内核态下
  // 关于内核中断的处理，在后面的博客中会仔细分析
  // 将stvec寄存器设置为kernelvec，当发生内核陷阱时会跳转到kernelvec而非之前的uservec
  w_stvec((uint64)kernelvec);

  // 获取当前进程
  struct proc *p = myproc();
  
  // save user program counter.
    // 将sepc再次保存一份到trapframe中去
  // xv6 book中说明这里之所以再次保存一份sepc
  // 是因为这里可能触发的是定时器中断，它会调用yield函数返回用户态
  // 从而导致原有的sepc被修改
  // 这涉及到CPU的调度和定时器中断，在后面的博客再进一步研究

  p->trapframe->epc = r_sepc();
  
    // 读取scause寄存器
  // 它是在我们调用ecall指令时由指令自动设置的
  // RISC-V标准定义，当scause的值为8时，表示陷阱原因是系统调用，详见下面的表格
  if(r_scause() == 8){
    // system call

    // 如果进程已经被杀死，那么直接退出 
    if(p->killed)
      exit(-1);

    // sepc points to the ecall instruction,
    // but we want to return to the next instruction.
    p->trapframe->epc += 4;

    // an interrupt will change sstatus &c registers,
    // so don't enable until done with those registers.
    intr_on();

    syscall();

    // 如果处理的是设备中断(interrupt)，则调用devintr来处理
  } else if((which_dev = devintr()) != 0){
    // ok
    if (which_dev == 2) {
      
        p->spend += 1;
        if (p->spend == p->interval && p->waiting){
          
          switchtrapframe(p->trapframe, p->handlertrapframe);
          p->trapframe->epc = (uint64)p->handler;
          p->waiting = 0;
          p->spend = 0;
        }
    }
    // 否则是异常(exception)，杀死当前进程并报错
  } else {
    printf("usertrap(): unexpected scause %p pid=%d\n", r_scause(), p->pid);
    printf("            sepc=%p stval=%p\n", r_sepc(), r_stval());
    p->killed = 1;
  }

  if(p->killed)
    exit(-1);


  // give up the CPU if this is a timer interrupt.
  // 译：如果是定时器中断，那么放弃当前CPU的使用权
  // 这里涉及CPU的调度，我们后面再仔细研究
  // give up the CPU if this is a timer interrupt.
  if(which_dev == 2)
    yield();

// 调用usertrapret完成陷阱处理返回
  usertrapret();
}

//
// return to user space
//
void
usertrapret(void)
{
  struct proc *p = myproc();

  // we're about to switch the destination of traps from
  // kerneltrap() to usertrap(), so turn off interrupts until
  // we're back in user space, where usertrap() is correct.
    // 译：我们将要把陷阱的目的地从kerneltrap改为usertrap
  // 所以直到回到用户模式且usertrap被正确设置之前，所有中断都被关闭
  intr_off();

  // send syscalls, interrupts, and exceptions to trampoline.S
    // 设置stvec寄存器，将stvec设置为uservec
  // 这是我们之前问题的答案，stvec寄存器就是在这里被设置指向uservec的
  // 你可能会说，这是一个鸡生蛋和蛋生鸡的问题，只有进程触发陷阱才会被设置stvec
  // 事实上，在fork一个新的进程时，因为fork是一个系统调用，那么它在返回到用户态时一定会经过这里
  // 从而在一开始成功设置了stvec寄存器
  w_stvec(TRAMPOLINE + (uservec - trampoline));

  // set up trapframe values that uservec will need when
  // the process next re-enters the kernel.
    // 译：设置trapframe中的值，这些值在下次uservec再次进入内核时会使用到
  // 分别设置：内核页表、内核栈指针、usertrap地址、CPU的ID号
  p->trapframe->kernel_satp = r_satp();         // kernel page table
  p->trapframe->kernel_sp = p->kstack + PGSIZE; // process's kernel stack
  p->trapframe->kernel_trap = (uint64)usertrap;
  p->trapframe->kernel_hartid = r_tp();         // hartid for cpuid()

  // set up the registers that trampoline.S's sret will use
  // to get to user space.
  
  // set S Previous Privilege mode to User.
    // 译：设置好trampoline.S中的sret指令会用到的寄存器，以返回用户态
  // 将前一个模式设置为用户态
  // 这里在为返回用户态做准备
  unsigned long x = r_sstatus();

    // 将SPP位清空，确保陷阱返回到用户模式
  // 设置SPIE为1，在返回时SPIE会被设置给SIE，确保supervisor模式下的中断被打开
  x &= ~SSTATUS_SPP; // clear SPP to 0 for user mode
  x |= SSTATUS_SPIE; // enable interrupts in user mode
  w_sstatus(x);

  // set S Exception Program Counter to the saved user pc.
  
  w_sepc(p->trapframe->epc);

  // tell trampoline.S the user page table to switch to.
  uint64 satp = MAKE_SATP(p->pagetable);

  // jump to trampoline.S at the top of memory, which 
  // switches to the user page table, restores user registers,
  // and switches to user mode with sret.
  uint64 fn = TRAMPOLINE + (userret - trampoline);
  ((void (*)(uint64,uint64))fn)(TRAPFRAME, satp);
}

// interrupts and exceptions from kernel code go here via kernelvec,
// on whatever the current kernel stack is.
void 
kerneltrap()
{
  int which_dev = 0;
  uint64 sepc = r_sepc();
  uint64 sstatus = r_sstatus();
  uint64 scause = r_scause();
  
  if((sstatus & SSTATUS_SPP) == 0)
    panic("kerneltrap: not from supervisor mode");
  if(intr_get() != 0)
    panic("kerneltrap: interrupts enabled");

  if((which_dev = devintr()) == 0){
    printf("scause %p\n", scause);
    printf("sepc=%p stval=%p\n", r_sepc(), r_stval());
    panic("kerneltrap");
  }

  // give up the CPU if this is a timer interrupt.
  if(which_dev == 2 && myproc() != 0 && myproc()->state == RUNNING)
    yield();

  // the yield() may have caused some traps to occur,
  // so restore trap registers for use by kernelvec.S's sepc instruction.
  w_sepc(sepc);
  w_sstatus(sstatus);
}

void
clockintr()
{
  acquire(&tickslock);
  ticks++;
  wakeup(&ticks);
  release(&tickslock);
}

// check if it's an external interrupt or software interrupt,
// and handle it.
// returns 2 if timer interrupt,
// 1 if other device,
// 0 if not recognized.
int
devintr()
{
  uint64 scause = r_scause();

  if((scause & 0x8000000000000000L) &&
     (scause & 0xff) == 9){
    // this is a supervisor external interrupt, via PLIC.

    // irq indicates which device interrupted.
    int irq = plic_claim();

    if(irq == UART0_IRQ){
      uartintr();
    } else if(irq == VIRTIO0_IRQ){
      virtio_disk_intr();
    } else if(irq){
      printf("unexpected interrupt irq=%d\n", irq);
    }

    // the PLIC allows each device to raise at most one
    // interrupt at a time; tell the PLIC the device is
    // now allowed to interrupt again.
    if(irq)
      plic_complete(irq);

    return 1;
  } else if(scause == 0x8000000000000001L){
    // software interrupt from a machine-mode timer interrupt,
    // forwarded by timervec in kernelvec.S.

    if(cpuid() == 0){
      clockintr();
    }
    
    // acknowledge the software interrupt by clearing
    // the SSIP bit in sip.
    w_sip(r_sip() & ~2);

    return 2;
  } else {
    return 0;
  }
}
 

