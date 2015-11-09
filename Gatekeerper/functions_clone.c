/*
 *
 *               ('-.     .-') _     ('-.  .-. .-')     ('-.     ('-.  _  .-')     _ (`-.    ('-.  _  .-')
 *              ( OO ).-.(  OO) )  _(  OO) \  ( OO )  _(  OO)  _(  OO)( \( -O )   ( (OO  ) _(  OO)( \( -O )
 *  ,----.      / . --. //     '._(,------.,--. ,--. (,------.(,------.,------.  _.`     \(,------.,------.
 *  '  .-./-')   | \-.  \ |'--...__)|  .---'|  .'   /  |  .---' |  .---'|   /`. '(__...--'' |  .---'|   /`. '
 *  |  |_( O- ).-'-'  |  |'--.  .--'|  |    |      /,  |  |     |  |    |  /  | | |  /  | | |  |    |  /  | |
 *  |  | .--, \ \| |_.'  |   |  |  (|  '--. |     ' _)(|  '--. (|  '--. |  |_.' | |  |_.' |(|  '--. |  |_.' |
 * (|  | '. (_/  |  .-.  |   |  |   |  .--' |  .   \   |  .--'  |  .--' |  .  '.' |  .___.' |  .--' |  .  '.'
 *  |  '--'  |   |  | |  |   |  |   |  `---.|  |\   \  |  `---. |  `---.|  |\  \  |  |      |  `---.|  |\  \
 *  `------'    `--' `--'   `--'   `------'`--' '--'  `------' `------'`--' '--' `--'      `------'`--' '--'
 *
 * Gatekeerper
 * A kernel extension to mitigate Gatekeeper bypasses
 * Doesn't let linked (frameworks, libraries, bundles) unsigned code run if main binary is signed
 *
 * Untested with latest Gatekeeper bypass, too lazy to create a PoC of that
 * So I'm just guessing it will work, I'm pretty confident anyway :P
 *
 * Not guaranteed to be secure code! It might even destroy your computer but that is your problem!
 *
 * Created by reverser on 01/10/15.
 * Copyright (c) fG!, 2015. All rights reserved.
 * reverser@put.as - https://reverse.put.as
 *
 * functions_clone.c
 *
 * Functions to clone and fix kernel functions
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "functions_clone.h"

#include <libkern/libkern.h>
#include <sys/sysctl.h>
#include <sys/kauth.h>
#include <sys/vnode.h>
#include <sys/stat.h>
#include <sys/malloc.h>
#include <mach-o/loader.h>

#include "logging.h"
#include "configuration.h"
#include "kernel_symbols.h"
#include "utils.h"

/* the island space */
extern char cloned_csfg_get_platform_binary[], cloned_csproc_get_teamid[], jump_island1[], jump_island2[], jump_island3[];

/* 
 * clone csfg_get_platform_binary, fix relocations, and patch it the way we need
 *
 * HARDCODED OFFSETS - Only valid for latest Yosemite 10.10.5
 *
 * This can be obviously improved using a disassembler but this is just a PoC
 * and things are stable enough to be ok this way
 *
 */
kern_return_t
clone_csfg_get_platform_binary(void)
{
    DEBUG_MSG("Address of cloned_space is %p", (void*)cloned_csfg_get_platform_binary);
    DEBUG_MSG("Address of csfg_get_platform_binary is %p", (void*)_csfg_get_platform_binary);
    DEBUG_MSG("Jump island 1 address %p", (void*)jump_island1);
    DEBUG_MSG("Jump island 2 address %p", (void*)jump_island2);
    
    void *_lck_mtx_lock = NULL;
    void *_lck_mtx_unlock = NULL;
    SOLVE_KERNEL_SYMBOL("_lck_mtx_lock", _lck_mtx_lock)
    SOLVE_KERNEL_SYMBOL("_lck_mtx_unlock", _lck_mtx_unlock)
    
    DEBUG_MSG("Locks %p and %p", _lck_mtx_lock, _lck_mtx_unlock);

    /* copy the function we want to clone into our cloned space */
    /* we need to disable kernel write protection to modify kext code - easier than calling mach_vm_protect */
    disable_interrupts();
    disable_wp();
    memcpy(cloned_csfg_get_platform_binary, (void*)_csfg_get_platform_binary, 100); // XXX: hardcoded size

    /* update first island - lck_mtx_lock */
    *(uint64_t*)(jump_island1 + 2) = (uint64_t)_lck_mtx_lock;
    /* update second island - lck_mtx_unlock */
    *(uint64_t*)(jump_island2 + 2) = (uint64_t)_lck_mtx_unlock;
    
    /* update calls to the islands in cloned function */
    *(int32_t*)(cloned_csfg_get_platform_binary + 0x1F) = (int32_t)(jump_island1 - (cloned_csfg_get_platform_binary + 0x1E + 5));
    *(int32_t*)(cloned_csfg_get_platform_binary + 0x48) = (int32_t)((jump_island2) - (cloned_csfg_get_platform_binary + 0x47 + 5));
    
    /* the original function returns csb_platform_binary
     * we patch it to return if uip->cs_blobs is NULL or not
     * meaning that it's code signed or not
     */
    *(int16_t*)(cloned_csfg_get_platform_binary + 0x41) = 0xC3FF; // inc ebx
    *(int8_t*)(cloned_csfg_get_platform_binary + 0x43) = 0x90;    // ebx is then moved to eax and default is NULL
    
    /* and we are ready to continue */
    enable_wp();
    enable_interrupts();
    return KERN_SUCCESS;
}

/*
 * clone csproc_get_teamid, fix relocations, and patch it the way we need
 *
 * HARDCODED OFFSETS - Only valid for latest Yosemite 10.10.5
 *
 * This can be obviously improved using a disassembler but this is just a PoC
 * and things are stable enough to be ok this way
 *
 */
kern_return_t
clone_csproc_get_teamid(void)
{
    DEBUG_MSG("Address of cloned_space is %p", (void*)cloned_csproc_get_teamid);
    DEBUG_MSG("Address of csproc_get_teamid is %p", (void*)_csproc_get_teamid);
    DEBUG_MSG("Jump island 3 address %p", (void*)jump_island3);

    /* copy the function we want to clone into our cloned space */
    /* we need to disable kernel write protection to modify kext code - easier than calling mach_vm_protect */
    disable_interrupts();
    disable_wp();

    /* clone _csproc_get_teamid and fix it with our patch */
    memcpy(cloned_csproc_get_teamid, (void*)_csproc_get_teamid, 100); // XXX: hardcoded size

    /* update _csproc_get_teamid island */
    *(uint64_t*)(jump_island3 + 2) = (uint64_t)_ubc_cs_blob_get;
    /* update calls to the islands in cloned function */
    *(int32_t*)(cloned_csproc_get_teamid + 0x29) = (int32_t)(jump_island3 - (cloned_csproc_get_teamid + 0x28 + 5));

    /* the original function returns a pointer
     * we modify it to return an int
     * 0 there's no code signing blob in current_proc() aka main binary not signed
     * 1 main binary is signed
     */
    *(uint32_t*)(cloned_csproc_get_teamid + 0x37) = 0x9090C0FF; // inc eax

    /* and we are ready to continue */
    enable_wp();
    enable_interrupts();
    return KERN_SUCCESS;
}
