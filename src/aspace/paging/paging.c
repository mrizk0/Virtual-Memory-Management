/* 
 * This file is part of the Nautilus AeroKernel developed
 * by the Hobbes and V3VEE Projects with funding from the 
 * United States National  Science Foundation and the Department of Energy.  
 *
 * The V3VEE Project is a joint project between Northwestern University
 * and the University of New Mexico.  The Hobbes Project is a collaboration
 * led by Sandia National Laboratories that includes several national 
 * laboratories and universities. You can find out more at:
 * http://www.v3vee.org  and
 * http://xstack.sandia.gov/hobbes
 *
 * Copyright (c) 2023, Nick Wanninger <ncw@u.northwestern.edu>
 * Copyright (c) 2019, Hongyi Chen
 * Copyright (c) 2019, Peter Dinda
 * Copyright (c) 2019, The V3VEE Project  <http://www.v3vee.org> 
 *                     The Hobbes Project <http://xstack.sandia.gov/hobbes>
 * All rights reserved.
 *
 * Authors: Nick Wanninger <ncw@u.northwestern.edu>
 *          Hongyi Chen
 *          Peter Dinda <pdinda@northwestern.edu>
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "LICENSE.txt".
 */


//
// This is a template for the CS343 paging lab at
// Northwestern University
//
// Please also look at the paging_helpers files!
//
//
//
//

#include <nautilus/nautilus.h>
#include <nautilus/spinlock.h>
#include <nautilus/paging.h>
#include <nautilus/thread.h>
#include <nautilus/shell.h>
#include <nautilus/cpu.h>

#include <nautilus/aspace.h>

#include "paging_helpers.h"


// For signal delivery
#ifdef NAUT_CONFIG_ENABLE_USERSPACE
#include <nautilus/user.h>
#endif


//
// Add debugging and other optional output to this subsytem
//
#ifndef NAUT_CONFIG_DEBUG_ASPACE_PAGING
#undef DEBUG_PRINT
#define DEBUG_PRINT(fmt, args...) 
#endif

#define ERROR(fmt, args...) ERROR_PRINT("aspace-paging: " fmt, ##args)
#define DEBUG(fmt, args...) DEBUG_PRINT("aspace-paging: " fmt, ##args)
#define INFO(fmt, args...)   INFO_PRINT("aspace-paging: " fmt, ##args)


// Some macros to hide the details of doing locking for
// a paging address space
#define ASPACE_LOCK_CONF uint8_t _aspace_lock_flags
#define ASPACE_LOCK(a) _aspace_lock_flags = spin_lock_irq_save(&(a)->lock)
#define ASPACE_TRY_LOCK(a) spin_try_lock_irq_save(&(a)->lock,&_aspace_lock_flags)
#define ASPACE_UNLOCK(a) spin_unlock_irq_restore(&(a)->lock, _aspace_lock_flags);
#define ASPACE_UNIRQ(a) irq_enable_restore(_aspace_lock_flags);


// graceful printouts of names
#define ASPACE_NAME(a) ((a)?(a)->aspace->name : "default")
#define THREAD_NAME(t) ((!(t)) ? "(none)" : (t)->is_idle ? "(idle)" : (t)->name[0] ? (t)->name : "(noname)")

#define NK_ASPACE_GET_READ(flags) ((flags & NK_ASPACE_READ) != 0)
#define NK_ASPACE_GET_WRITE(flags) ((flags & NK_ASPACE_WRITE) != 0)
#define NK_ASPACE_GET_EXEC(flags) ((flags & NK_ASPACE_EXEC) != 0)
#define NK_ASPACE_GET_PIN(flags) ((flags & NK_ASPACE_PIN) != 0)
#define NK_ASPACE_GET_KERN(flags) ((flags & NK_ASPACE_KERN) != 0)
#define NK_ASPACE_GET_SWAP(flags) ((flags & NK_ASPACE_SWAP) != 0)
#define NK_ASPACE_GET_EAGER(flags) ((flags & NK_ASPACE_EAGER) != 0)
#define NK_ASPACE_GET_FILE(flags) ((flags & NK_ASPACE_FILE) != 0)
#define NK_ASPACE_GET_ANON(flags) ((flags & NK_ASPACE_ANON) != 0)

// You probably want some sort of data structure that will let you
// keep track of the set of regions you are asked to add/remove/change
// (Task 2)
typedef struct region_node {
    nk_aspace_region_t region;
    //
    // WRITEME!!    linked list?  tree?  ??
    // 
    struct region_node *next, *prev;
} region_node_t;

// You will want some data structure to represent the state
// of a paging address space
typedef struct nk_aspace_paging {
    // pointer to the abstract aspace that the
    // rest of the kernel uses when dealing with this
    // address space
    nk_aspace_t *aspace;
    
    // perhaps you will want to do concurrency control?
    spinlock_t   lock;

    // Here you probably will want your region set data structure 
    // What should it be...
    
    // Your characteristics
    nk_aspace_characteristics_t chars;

    // The cr3 register contents that reflect
    // the root of your page table hierarchy
    ph_cr3e_t     cr3;

    // The cr4 register contents used by the HW to interpret
    // your page table hierarchy.   We only care about a few bits
#define CR4_MASK 0xb0ULL // bits 4,5,7
    uint64_t      cr4;
	
    //
    // WRITEME!!    Any additional data you need to track
    // 
    region_node_t *node_head;
} nk_aspace_paging_t;



// The function the aspace abstraction will call when it
// wants to destroy your address space (free all the associated memory)
static  int destroy(void *state)
{
    // the pointer it hands you is for the state you supplied
    // when you registered the address space
    nk_aspace_paging_t *p = (nk_aspace_paging_t *)state;

    DEBUG("destroying address space %s\n", ASPACE_NAME(p));

    ASPACE_LOCK_CONF;

    // lets do that with a lock, perhaps? 
    ASPACE_LOCK(p);
    region_node_t *node = p->node_head;

    while(node != NULL){
        region_node_t *next = node->next;
        free(node);
        node = next;
    }
    ASPACE_UNLOCK(p);

    return 0;
}

// The function the aspace abstraction will call when it
// is adding a thread to your address space
// do you care? 
static int add_thread(void *state)
{
    nk_aspace_paging_t *p = (nk_aspace_paging_t *)state;
    struct nk_thread *t = get_cur_thread();
    
    DEBUG("adding thread %d (%s) to address space %s\n", t->tid,THREAD_NAME(t), ASPACE_NAME(p));
    
    return 0;
}
    
    
// The function the aspace abstraction will call when it
// is removing from your address space
// do you care? 
static int remove_thread(void *state)
{
    nk_aspace_paging_t *p = (nk_aspace_paging_t *)state;
    struct nk_thread *t = get_cur_thread();
    
    DEBUG("removing thread %d (%s) from address space %s\n", t->tid, THREAD_NAME(t), ASPACE_NAME(p));
    
    return 0;
}


// The function the aspace abstraction will call when it
// is adding a region to your address space
static int add_region(void *state, nk_aspace_region_t *region)
{
    // add the new node into region_list
    nk_aspace_paging_t *p = (nk_aspace_paging_t *)state;


    DEBUG("adding region (va=%016lx pa=%016lx len=%lx) to address space %s\n", region->va_start, region->pa_start, region->len_bytes,ASPACE_NAME(p));

    ASPACE_LOCK_CONF;

    ASPACE_LOCK(p);
    region_node_t *node = p->node_head;

    uint64_t insert_va = (uint64_t)region->va_start;
    uint64_t insert_total_size = (uint64_t)region->len_bytes;
    //DEBUG("**************************************************************************\n");
    //DEBUG("Trying to insert address start at %016lx and finish at %016lx\n\n", insert_va,  insert_va + insert_total_size);


    while(node != NULL){
        //check overlap
        
        uint64_t found_va = (uint64_t)node->region.va_start;
        uint64_t found_total_size = (uint64_t)node->region.len_bytes;

        DEBUG("Found region with address start at %016lx and finish at %016lx\n\n", found_va, found_va +found_total_size);

        if((insert_va < found_va + found_total_size) &&
           (insert_va + insert_total_size > found_va)){
            DEBUG("FAILED TO FIND NON OVERLAPPING REGION\n");
            ASPACE_UNLOCK(p);
            return -1;
           }
        node = node->next;
    }

    // add region to linked list
    region_node_t *new_node = (region_node_t *)malloc(sizeof(region_node_t));
    new_node->region = *(region);
    p->node_head->prev = new_node;
    new_node->next = p->node_head;
    p->node_head = new_node;

    // WRITE ME!!
    
    // first you should sanity check the region to be sure it doesn't overlap
    // an existing region, and then place it into your region data structure

    // NOTE: you MUST create a new nk_aspace_region_t to store in your data structure
    // and you MAY NOT store the region pointer in your data structure. There is no
    // promise that data at the region pointer will not be modified after this function
    // returns

    if (region->protect.flags & NK_ASPACE_EAGER) {
	
         uint64_t num_pages = region->len_bytes / PAGE_SIZE_4KB;
        ph_pf_access_t access;
        access.write = NK_ASPACE_GET_WRITE(region->protect.flags);
        access.present = 1;
        access.ifetch = NK_ASPACE_GET_EXEC(region->protect.flags);
        access.rsvd_access = 0;
        access.rsvd = 0;
        access.user = NK_ASPACE_GET_KERN(region->protect.flags) ? 0 : 1;
        uint64_t va = (uint64_t)region->va_start; 

        //if region is file backed or anonymous
        if ((region->protect.flags & NK_ASPACE_FILE) || (region->protect.flags & NK_ASPACE_ANON)) {
            for (uint64_t i = 0; i < num_pages; i++) {
                void* pa = malloc(4096);
                if (region->protect.flags & NK_ASPACE_FILE) {
                    nk_fs_seek(region->file, i * 4096, 0);
                    nk_fs_read(region->file, pa, 4096);
                } else {
                    memset(pa, 0, PAGE_SIZE_4KB);
                }
                paging_helper_drill(p->cr3, va, pa, access);
                va += PAGE_SIZE_4KB;
            }
        //if region is normal
        } else {
            uint64_t pa = (uint64_t)region->pa_start;
            for (uint64_t i = 0; i < num_pages; i++) {
                paging_helper_drill(p->cr3, va, pa, access);
                va += PAGE_SIZE_4KB;
                pa += PAGE_SIZE_4KB;
        // In task 5, you need to handle file-backed and anonymous mappings.
	// Make sure to design for this requirement early!
    }}
    }

    // if we are editing the current address space of this cpu, then we
    // might need to flush the TLB here.   We can do that with a cr3 write
    // like: write_cr3(p->cr3.val);

    struct cpu *cpu = get_cpu();
    nk_aspace_t *cur = cpu->cur_aspace;

    if (cur->name == p->aspace->name){
        write_cr3(p->cr3.val);
    }


    // if this aspace is active on a different cpu, we might need to do
    // a TLB shootdown here (out of scope of class)
    // a TLB shootdown is an interrupt to a remote CPU whose handler
    // flushes the TLB

    ASPACE_UNLOCK(p);
    
    return 0;
}

// The function the aspace abstraction will call when it
// is removing a region from your address space
static int remove_region(void *state, nk_aspace_region_t *region)
{
    nk_aspace_paging_t *p = (nk_aspace_paging_t *)state;

    DEBUG("removing region (va=%016lx pa=%016lx len=%lx) from address space %s\n", region->va_start, region->pa_start, region->len_bytes,ASPACE_NAME(p));

    ASPACE_LOCK_CONF;

    ASPACE_LOCK(p);

    // WRITE ME!!
    
    // first, find the region in your data structure
    // it had better exist and be identical.
    region_node_t *current_node = p->node_head;
    
    while (current_node != NULL){

        if (current_node->region.va_start == region->va_start){
            if (current_node->region.len_bytes == region->len_bytes){
                if (current_node->region.protect.flags == region->protect.flags){
                    if (current_node->region.pa_start == region->pa_start){
                        break;
                    }
                }   
            }
            
        }
        
        current_node = current_node->next;
    }

    if (NK_ASPACE_GET_PIN(current_node->region.protect.flags)){
        ASPACE_UNLOCK(p);
        return -1;
    }

    // next, remove the region from your data structure

    region_node_t *prev_region = current_node->prev;
    region_node_t *next_region = current_node->next;

    if (prev_region == NULL){
        p->node_head = next_region;
    }
    else{
        prev_region->next = next_region;
        next_region->prev = prev_region;
    }

    free(current_node);

    // next, remove all corresponding page table entries that exist.
    // Make sure to handle anonymous and file-backed mappings. For task 5,
    // remember to free() the file-backed and anonymous memory you allocated
    // in add_region and exception.

    
	
        

	// DRILL THE PAGE TABLES HERE
        uint64_t num_pages = region->len_bytes / PAGE_SIZE_4KB;
        ph_pf_access_t access;
        access.write = 0;
        access.present = 0;
        access.ifetch = 0;
        access.rsvd_access = 0;
        access.rsvd = 0;
        access.user = 0;
        uint64_t va = (uint64_t)region->va_start;
        uint64_t pa = (uint64_t)region->pa_start;
        for (uint64_t i = 0; i < num_pages; i++) {
            if ((region->protect.flags & NK_ASPACE_FILE) || (region->protect.flags & NK_ASPACE_ANON)) {
                uint64_t ** entry;
                paging_helper_walk(p->cr3, va, access, entry);
                pa = ((addr_t)**entry) << 12;
                free(pa);
            } else {
                pa = (uint64_t)region->pa_start + (i*PAGE_SIZE_4KB);
            }
            paging_helper_drill(p->cr3, va, pa, access);
            va += PAGE_SIZE_4KB;
    }

    // next, if we are editing the current address space of this cpu,
    // we need to either invalidate individual pages using invlpg()
    // or do a full TLB flush with a write to cr3.
    struct cpu *cpu = get_cpu();
    nk_aspace_t *cur = cpu->cur_aspace;

    if (cur->name == p->aspace->name){
        write_cr3(p->cr3.val);
    }

    ASPACE_UNLOCK(p);

    return 0;

}
   
// The function the aspace abstraction will call when it
// is changing the protections of an existing region
static int protect_region(void *state, nk_aspace_region_t *region, nk_aspace_protection_t *prot)
{
    nk_aspace_paging_t *p = (nk_aspace_paging_t *)state;

    DEBUG("protecting region (va=%016lx pa=%016lx len=%lx) from address space %s\n", region->va_start, region->pa_start, region->len_bytes,ASPACE_NAME(p));

    ASPACE_LOCK_CONF;

    ASPACE_LOCK(p);

    // WRITE ME!!
    
    // first, find the region in your data structure
    // it had better exist and be identical except for protections
    region_node_t *current_node = p->node_head;
    
    while (current_node != NULL){

        if (current_node->region.va_start == region->va_start){
            if (current_node->region.len_bytes == region->len_bytes){
                if (current_node->region.protect.flags == region->protect.flags){
                    if (current_node->region.pa_start == region->pa_start){
                        break;
                    }
                }   
            }
            
        }
        
        current_node = current_node->next;
    }

    // next, update the region protections from your data structure
	if (!current_node) {
        ASPACE_UNLOCK(p);
        return -1;
    }

    current_node->region.protect = *(prot);

    // next, update all corresponding page table entries that exist

    if (current_node->region.protect.flags & NK_ASPACE_EAGER) {
	
        // an eager region means that we need to build all the corresponding
        // page table entries right now, before we return

        // DRILL THE PAGE TABLES HERE
        uint64_t num_pages = region->len_bytes / PAGE_SIZE_4KB;
        ph_pf_access_t access;
        access.write = NK_ASPACE_GET_WRITE(current_node->region.protect.flags);
        access.present = 1;
        access.ifetch = 1;
        access.rsvd_access = 0;
        access.rsvd = 0;
        access.user = 0;
        uint64_t va = (uint64_t)region->va_start;
        uint64_t pa = (uint64_t)region->pa_start;
        for (uint64_t i = 0; i < num_pages; i++) {
            paging_helper_drill(p->cr3, va, pa, access);
            va += PAGE_SIZE_4KB;
            pa += PAGE_SIZE_4KB;
        // In task 5, you need to handle file-backed and anonymous mappings.
	// Make sure to design for this requirement early!
    }}

    // next, if we are editing the current address space of this cpu,
    // we need to either invalidate individual pages using invlpg()
    // or do a full TLB flush with a write to cr3.
	struct cpu *cpu = get_cpu();
    nk_aspace_t *cur = cpu->cur_aspace;

    if (cur->name == p->aspace->name){
        write_cr3(p->cr3.val);
    }

    ASPACE_UNLOCK(p);

    return 0;
}

static int move_region(void *state, nk_aspace_region_t *cur_region, nk_aspace_region_t *new_region)
{
    nk_aspace_paging_t *p = (nk_aspace_paging_t *)state;

    DEBUG("moving region (va=%016lx pa=%016lx len=%lx) in address space %s to (va=%016lx pa=%016lx len=%lx)\n", cur_region->va_start, cur_region->pa_start, cur_region->len_bytes,ASPACE_NAME(p),new_region->va_start,new_region->pa_start,new_region->len_bytes);

    ASPACE_LOCK_CONF;

    ASPACE_LOCK(p);

    // WRITE ME!!
    
    // first, find the region in your data structure
    // it had better exist and be identical except for the physical addresses
    region_node_t *current_node = p->node_head;
    
    while (current_node != NULL){

        if (current_node->region.va_start == cur_region->va_start){
            if (current_node->region.len_bytes == cur_region->len_bytes){
                if (current_node->region.protect.flags == cur_region->protect.flags){
                    break;
                }   
            }
        }
        
        current_node = current_node->next;
    }

    if (NK_ASPACE_GET_PIN(current_node->region.protect.flags)){
        ASPACE_UNLOCK(p);
        return -1;
    }

    // next, update the region in your data structure

    current_node->region = *(new_region);

    // you can assume that the caller has done the work of copying the memory
    // contents to the new physical memory

    // next, update all corresponding page table entries that exist

    if (current_node->region.protect.flags & NK_ASPACE_EAGER) {
	
        // an eager region means that we need to build all the corresponding
        // page table entries right now, before we return

        // DRILL THE PAGE TABLES HERE
        uint64_t num_pages = current_node->region.len_bytes / PAGE_SIZE_4KB;
        ph_pf_access_t access;
        access.write = NK_ASPACE_GET_WRITE(current_node->region.protect.flags);
        access.present = 1;
        access.ifetch = 1;
        access.rsvd_access = 0;
        access.rsvd = 0;
        access.user = 0;
        uint64_t va = (uint64_t)current_node->region.va_start;
        uint64_t pa = (uint64_t)current_node->region.pa_start;
        for (uint64_t i = 0; i < num_pages; i++) {
            paging_helper_drill(p->cr3, va, pa, access);
            va += PAGE_SIZE_4KB;
            pa += PAGE_SIZE_4KB;
        // In task 5, you need to handle file-backed and anonymous mappings.
	// Make sure to design for this requirement early!
    }}

    // next, if we are editing the current address space of this cpu,
    // we need to either invalidate individual pages using invlpg()
    // or do a full TLB flush with a write to cr3.

    struct cpu *cpu = get_cpu();
    nk_aspace_t *cur = cpu->cur_aspace;

    if (cur->name == p->aspace->name){
        write_cr3(p->cr3.val);
    }


    // OPTIONAL ADVANCED VERSION: allow for splitting the region - if cur_region
    // is a subset of some region, then split that region, and only move
    // the affected addresses.   The granularity of this is that reported
    // in the aspace characteristics (i.e., page granularity here).

    ASPACE_UNLOCK(p);

    return 0;
}


// Called by the address space abstraction when it is switching away from
// the noted address space.   This is part of the thread context switch.
// do you care?
static int switch_from(void *state)
{
    struct nk_aspace_paging *p = (struct nk_aspace_paging *)state;
    struct nk_thread *thread = get_cur_thread();
    
    DEBUG("switching out address space %s from thread %d (%s)\n",ASPACE_NAME(p), thread->tid, THREAD_NAME(thread));
    
    return 0;
}

// Called by the address space abstraction when it is switching to the
// noted address space.  This is part of the thread context switch.
static int switch_to(void *state)
{
    nk_aspace_paging_t *p = (nk_aspace_paging_t *)state;
    struct nk_thread *thread = get_cur_thread();
    
    DEBUG("switching in address space %s from thread %d (%s)\n", ASPACE_NAME(p),thread->tid,THREAD_NAME(thread));
    
    // Here you will need to install your page table hierarchy
    // first point CR3 to it
    write_cr3(p->cr3.val);

    // next make sure the interpretation bits are set in cr4
    uint64_t cr4 = read_cr4();
    cr4 &= ~CR4_MASK;
    cr4 |= p->cr4;
    write_cr4(cr4);
    
    return 0;
}

// Called by the address space abstraction when a page fault or a
// general protection fault is encountered in the context of the
// current thread
//
// exp points to the hardware interrupt frame on the stack
// vec indicates which vector happened
//
static int exception(void *state, excp_entry_t *exp, excp_vec_t vec)
{
    nk_aspace_paging_t *p = (nk_aspace_paging_t *)state;
    struct nk_thread *thread = get_cur_thread();
    
    DEBUG("exception 0x%x for address space %s in context of thread %d (%s)\n",vec,ASPACE_NAME(p),thread->tid,THREAD_NAME(thread));
    
    if (vec==GP_EXCP) {
	ERROR("general protection fault encountered.... uh...\n");
	ERROR("i have seen things that you people would not believe.\n");
	// Maybe deliver a signal to a userspace process instead of panicing (or exit the current thread)?
	panic("general protection fault delivered to paging subsystem\n");
	return -1; // will never happen
    }

    if (vec!=PF_EXCP) {
	ERROR("Unknown exception %d delivered to paging subsystem\n",vec);
	// Maybe deliver a signal to a userspace process instead of panicing (or exit the current thread)?
	panic("Unknown exception delivered to paging subsystem\n");
	return -1; // will never happen
    }
    
    // It must be a page fault
    
    // find out what the address caused the fault, as well as the reason
    uint64_t virtaddr = read_cr2();
    ph_pf_error_t  error;
    error.val = exp->error_code;
    
    
    ASPACE_LOCK_CONF;
    
    ASPACE_LOCK(p);

    //
    // WRITE ME!!
    //
    
    // Now find the region corresponding to this address
    region_node_t *node = p->node_head;
    nk_aspace_region_t *region = NULL;
    while(node){
        if ((virtaddr >= (uint64_t)node->region.va_start) && (virtaddr <= ((uint64_t)node->region.va_start + node->region.len_bytes))){
            region = &node->region;
            break;
        }
        node = node->next;
    }
    

    // if there is no such region, this is an unfixable fault
    //  - if it's within an interrupt handler, the kernel should panic
    //  - if this is a user thread (nk_thread_is_user_thread(thread) from nautilus/user.h),
    //    we would signal with `return set_pending_signal();`
    //  - if it's a kernel thread, the kernel should panic
    if(region == NULL){
        if(!nk_thread_is_user_thread(thread)){
            panic("Interrupt handler or kernel thread");
        }
        else{
            ASPACE_UNLOCK(p);
            return set_pending_signal();
        }
    }



    // Is the problem that the page table entry is not present?
    // if so, drill the entry and then return from the function
    // so the faulting instruction can try again
    //  - This is the lazy construction of the page table entries
    //  - Be sure to handle anonymous and file-backed mappings like you do add_region. 
    if(!error.present){
        ph_pf_access_t access;
        access.write = NK_ASPACE_GET_WRITE(region->protect.flags);
        access.present = 1;
        access.ifetch = NK_ASPACE_GET_EXEC(region->protect.flags);
        access.rsvd_access = 0;
        access.rsvd = 0;
        access.user = NK_ASPACE_GET_KERN(region->protect.flags) ? 0 : 1;
        addr_t pa;
        
        if ((region->protect.flags & NK_ASPACE_FILE) || (region->protect.flags & NK_ASPACE_ANON)) {
            //allocate the physical memory
            pa = malloc(4096);
            if (region->protect.flags & NK_ASPACE_FILE) {
                //if file backed, read file into memory
                uint64_t page_offset = PAGE_ADDR_4KB(virtaddr) - (uint64_t)region->va_start;
                nk_fs_seek(region->file, page_offset, 0);
                nk_fs_read(region->file, pa, 4096);
            } else {
                //if anonymous, set physical memory to 0
                memset(pa, 0, PAGE_SIZE_4KB);
            }
        } else {
            pa = (addr_t)region->pa_start + (virtaddr - (uint64_t)region->va_start);
        }
        paging_helper_drill(p->cr3, PAGE_ADDR_4KB(virtaddr), pa, access);
        ASPACE_UNLOCK(p);
        return 0;
    }



    // Assuming the page table entry is present, check the region's
    // protections and compare to the error code

    // if the region has insufficient permissions for the request,
    //  - if it's within an interrupt handler, the kernel should panic
    //  - if this is a user thread (nk_thread_is_user_thread(thread) from nautilus/user.h),
    //    we would signal with `return set_pending_signal();`
    //  - if it's a kernel thread, the kernel should panic
    if(error.present){
        if(error.write != NK_ASPACE_GET_WRITE(region->protect.flags) ||
           error.user == NK_ASPACE_GET_KERN(region->protect.flags) ||
           error.ifetch != NK_ASPACE_GET_EXEC(region->protect.flags)){
            if(!nk_thread_is_user_thread(thread)){
                panic("Interrupt handler or kernel thread");
            }
            else{
                return set_pending_signal();
            }
    }}
    
    ASPACE_UNLOCK(p);
    
    return 0;
}
    
// called by the address space abstraction when it wants you
// to print out info about the address space.  detailed is
// nonzero if it wants a detailed output.  Use the nk_vc_printf()
// function to print here
static int print(void *state, int detailed)
{
    nk_aspace_paging_t *p = (nk_aspace_paging_t *)state;
    struct nk_thread *thread = get_cur_thread();
    

    // basic info
    nk_vc_printf("%s: paging address space [granularity 0x%lx alignment 0x%lx]\n"
		 "   CR3:    %016lx  CR4m: %016lx\n",
		 ASPACE_NAME(p), p->chars.granularity, p->chars.alignment, p->cr3.val, p->cr4);

    if (detailed) {
        // print region set data structure here

        // perhaps print out all the page tables here...
    }

    return 0;
}    

//
// This structure binds together your interface functions
// with the interface definition of the address space abstraction
// it will be used later in registering an address space
//
static nk_aspace_interface_t paging_interface = {
    .destroy = destroy,
    .add_thread = add_thread,
    .remove_thread = remove_thread,
    .add_region = add_region,
    .remove_region = remove_region,
    .protect_region = protect_region,
    .move_region = move_region,
    .switch_from = switch_from,
    .switch_to = switch_to,
    .exception = exception,
    .print = print
};


//
// The address space abstraction invokes this function when
// someone asks about your implementations characterstics
//
static int   get_characteristics(nk_aspace_characteristics_t *c)
{
    // you must support 4KB page granularity and alignment
    c->granularity = c->alignment = PAGE_SIZE_4KB;
    
    return 0;
}


//
// The address space abstraction invokes this function when
// someone wants to create a new paging address space with the given
// name and characteristics
//
static struct nk_aspace * create(char *name, nk_aspace_characteristics_t *c)
{
    struct naut_info *info = nk_get_nautilus_info();
    nk_aspace_paging_t *p;
    
    p = malloc(sizeof(*p));
    
    if (!p) {
	ERROR("cannot allocate paging aspace %s\n",name);
	return 0;
    }
  
    memset(p,0,sizeof(*p));
    
    spinlock_init(&p->lock);

    // copy the characteristics
    p->chars = *c;

    // initialize your region set data structure here!
    //
    // WRITE ME!!
    //

    // create an initial top-level page table (PML4)
    if(paging_helper_create(&(p->cr3)) == -1){
	ERROR("unable create aspace cr3 in address space %s\n", name);
    }

    // note also the cr4 bits you should maintain
    p->cr4 = nk_paging_default_cr4() & CR4_MASK;


    // if we supported address spaces other than long mode
    // we would also manage the EFER register here

    // Register your new paging address space with the address space
    // space abstraction
    // the registration process returns a pointer to the abstract
    // address space that the rest of the system will use
    p->aspace = nk_aspace_register(name,
				   // we want both page faults and general protection faults
				   NK_ASPACE_HOOK_PF | NK_ASPACE_HOOK_GPF,
				   // our interface functions (see above)
				   &paging_interface,
				   // our state, which will be passed back
				   // whenever any of our interface functiosn are used
				   p);
    
    if (!p->aspace) {
	ERROR("Unable to register paging address space %s\n",name);
	return 0;
    }
    
    DEBUG("paging address space %s configured and initialized (returning %p)\n", name, p->aspace);
    
    // you are returning
    return p->aspace; 
}

//
// This structure binds together the interface functions of our
// implementation with the relevant interface definition
static nk_aspace_impl_t paging = {
				.impl_name = "paging",
				.get_characteristics = get_characteristics,
				.create = create,
};


// this does linker magic to populate a table of address space
// implementations by including this implementation
nk_aspace_register_impl(paging);


