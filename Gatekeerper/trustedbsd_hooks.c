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
 * trustedbsd_hooks.c
 *
 * Functions to replace AMFI hooks and control unsigned code
 * Where all the magic happens!
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

#include "trustedbsd_hooks.h"

#include <libkern/libkern.h>
#include <sys/sysctl.h>
#include <sys/kauth.h>
#include <sys/vnode.h>
#include <sys/stat.h>
#include <sys/malloc.h>
#include <mach-o/loader.h>
#define CONFIG_MACF 1
#include <security/mac_framework.h>
#include <security/mac.h>
#include <security/mac_policy.h>
#include <Availability.h>

#include "logging.h"
#include "configuration.h"
#include "kernel_symbols.h"
#include "utils.h"
#include "functions_clone.h"

extern const int version_major;
extern const int version_minor;
extern char cloned_csfg_get_platform_binary[], cloned_csproc_get_teamid[];

static void *original_amfi_hook = NULL;
static int amfi_driver_position = -1;

/* structures and definitions */

/* NOTE: these structures are internal to TrustedBSD and not exposed in public includes */
/* they are stable since the initial implementation but we still have some risk in defining them here */
struct mac_policy_list_element {
    struct mac_policy_conf *mpc;
};

struct mac_policy_list {
    u_int				numloaded;
    u_int 				max;
    u_int				maxindex;
    u_int				staticmax;
    u_int				chunks;
    u_int				freehint;
    struct mac_policy_list_element	*entries;
};

typedef struct mac_policy_list mac_policy_list_t;

mach_vm_address_t g_mac_policy_list; /* address of mac_policy_list kernel variable */

/* the hook definition changed between Yosemite and El Capitan */
typedef int mpo_file_check_mmap_14_t(
                                  kauth_cred_t cred,
                                  struct fileglob *fg,
                                  struct label *label,
                                  int prot,
                                  int flags,
                                  int *maxprot
                                  );

mpo_file_check_mmap_14_t gatekeerper_hook_file_check_mmap_14;

/* these are our modified prototypes for our modified cloned functions */
typedef int csfg_get_platform_binary_t(struct fileglob *fg);
typedef int csproc_get_teamid_t(struct proc *p);

#pragma mark -
#pragma mark Start and stop functions

/*
 * replace Yosemite AMFI check_file_mmap hook with our own to control the mmap hook
 * 
 */
kern_return_t
start_trustedbsd_hooks(void *d)
{
    /* only support for Yosemite at the moment! */
    if (version_major != 14)
    {
        ERROR_MSG("Unsupported OS X version!");
        return KERN_FAILURE;
    }

    /* find where AMFI hooks are */
    /* Only relevant for Yosemite, El Capitan, and maybe higher */
    if (version_major == 14) // Yosemite
    {
        DEBUG_MSG("Replacing AMFI hook...");
        
        /* clone the functions we need inside our modified hook */
        if (clone_csfg_get_platform_binary() != KERN_SUCCESS)
        {
            ERROR_MSG("Can't clone csfg_get_platform_binary.");
            return KERN_FAILURE;
        }
        if (clone_csproc_get_teamid() != KERN_SUCCESS)
        {
            ERROR_MSG("Can't clone csproc_get_teamid.");
            return KERN_FAILURE;
        }
        
        /* we have the cloned functions ready
         * so next step is to exchange the AMFI hook with our version
         * that will use our cloned functions
         * and then return to the original AMFI hook
         */
        
        /* retrieve location of TrustedBSD base structure */
        SOLVE_KERNEL_VARIABLE("_mac_policy_list", g_mac_policy_list)
        /* find where AMFI is loaded */
        struct mac_policy_list policy_list = *(struct mac_policy_list*)g_mac_policy_list;
        for (int i = 0; i < policy_list.numloaded; i++)
        {
            struct mac_policy_conf *mpc = policy_list.entries[i].mpc;
            if (mpc != NULL)
            {
                if (strcmp(mpc->mpc_name, "AMFI") == 0)
                {
                    DEBUG_MSG("Found AMFI driver %d.", i);
                    amfi_driver_position = i;
                    break;
                }
            }
        }
        /* if we don't know where AMFI is we can't do anything */
        if (amfi_driver_position == -1)
        {
            ERROR_MSG("No idea where AMFI position is. Can't proceed!");
            return KERN_FAILURE;
        }
        
        /* exchange hook inside AMFI driver */
        /* hook prototype changed between Yosemite and El Capitan */
        DEBUG_MSG("Ready to exchange AMFI hooks...");
        disable_interrupts();
        struct mac_policy_conf *temp = policy_list.entries[amfi_driver_position].mpc;
        struct mac_policy_ops *ops = temp->mpc_ops;
        switch (version_major) {
            case 14:
            {
                original_amfi_hook = (void*)ops->mpo_file_check_mmap;
                ops->mpo_file_check_mmap = (void*)gatekeerper_hook_file_check_mmap_14;
                break;
            }
            default:
            {
                ERROR_MSG("Unsupported OS X version.");
                enable_interrupts();
                return KERN_FAILURE;
            }
        }
        enable_interrupts();
        DEBUG_MSG("Replaced AMFI hook, Gatekeerper is now active.");
        return KERN_SUCCESS;
    }
    
    return KERN_FAILURE;
}

/* restore original AMFI hook */
kern_return_t
stop_trustedbsd_hooks(void)
{
    if (version_major >= 14 && amfi_driver_position != -1)
    {
        disable_interrupts();
        struct mac_policy_list policy_list = *(struct mac_policy_list*)g_mac_policy_list;
        struct mac_policy_conf *temp = policy_list.entries[amfi_driver_position].mpc;
        struct mac_policy_ops *ops = temp->mpc_ops;
        switch (version_major) {
            case 14:
            {
                ops->mpo_file_check_mmap = (void*)original_amfi_hook;
                break;
            }
            default:
            {
                ERROR_MSG("Unsupported OS X version.");
                enable_interrupts();
                return KERN_FAILURE;
            }
        }
        enable_interrupts();
        DEBUG_MSG("AMFI original hook restored.");
    }
    return KERN_SUCCESS;
}

#pragma mark -
#pragma mark The Hooks

/* Our Yosemite AMFI hook*/
int
gatekeerper_hook_file_check_mmap_14(
                                    kauth_cred_t cred,
                                    struct fileglob *fg,
                                    struct label *label,
                                    int prot,
                                    int flags,
                                    int *maxprot
                                    )
{
    char binary_path[MAXPATHLEN] = {0};
    int pathbuff_len = sizeof(binary_path);
    
    int result = 0;
    
    /* try to get some info about what is being mmap'ed */
    result = _csfg_get_path(fg, binary_path, &pathbuff_len);
    /* we only want to mess around with executable stuff */
    if (result == 0 && (prot & 0x4))
    {
        /* the platform binary field is not good enough for our purpose
         * so we need to use our cloned and patched functions
         * to understand if the mmap'ed binary is code signed
         * and if the main proc is also code signed
         * 
         * not pretty but there's no full support in XNU to gather useful info from
         * code signing
         * It has improved in El Capitan but far from useful to external devs and hackers ;-)
         */
        
        /* first, get the status of the main proc */
        proc_t p = current_proc();
        if (p == (struct proc *)0)
        {
            ERROR_MSG("Can't retrieve current proc.");
            /* XXX: deny access */
            return 1;
        }
        
        /* verify is main process is signed or not
         * this could also be used to deny running any unsigned process
         */
        int is_main_signed = ((csproc_get_teamid_t*)(void*)(cloned_csproc_get_teamid))(p);
        /* just some debug code, can be removed */
        if (is_main_signed == 0)
        {
            DEBUG_MSG("current_proc is not signed");
        }
        
        /* verify if the binary code trying to be mapped is signed or not
         * we don't let unsigned code run if the main binary is signed
         */
        int is_mapped_signed = ((csfg_get_platform_binary_t*)cloned_csfg_get_platform_binary)(fg);
        if (is_mapped_signed == 0 && is_main_signed == 1)
        {
            ERROR_MSG("mmap'ed executable %s is not code signed for a signed main proc", binary_path);
            /* XXX: this will make the process crash because it can't load the linked external code */
            /* shouldn't we just kill it? we have current_proc() anyway */
            return 1;
        }
    }
    /* we can't get info about what is being mapped
     * what is the decision here? deny access?
     * for now just log the error and pass control to original AMFI hook
     */
    else if (result != 0)
    {
        ERROR_MSG("Failed to get path: %d", result);
    }
    
    /* pass control back to AMFI */
    return ((mpo_file_check_mmap_14_t*)original_amfi_hook)(cred, fg, label, prot, flags, maxprot);
}
