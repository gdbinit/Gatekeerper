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
 * TESTED ONLY WITH YOSEMITE 10.10.5 - EVERYTHING ELSE = KERNEL PANIC!
 *
 * Created by reverser on 01/10/15.
 * Copyright (c) fG!, 2015. All rights reserved.
 * reverser@put.as - https://reverse.put.as
 *
 * Gatekeerper.c
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

#include <mach/mach_types.h>
#include "logging.h"
#include "configuration.h"
#include "kernel_symbols.h"
#include "trustedbsd_hooks.h"
#include <kern/locks.h>

/* global variables */
/* structure to hold kernel headers info we use to solve symbols */
struct kernel_info g_kinfo;

extern const int version_major;
extern const int version_minor;
extern const int version_revision;

kern_return_t Gatekeerper_start(kmod_info_t * ki, void *d);
kern_return_t Gatekeerper_stop(kmod_info_t *ki, void *d);

kern_return_t Gatekeerper_start(kmod_info_t * ki, void *d)
{
    /* TESTED ONLY WITH YOSEMITE 10.10.5 - EVERYTHING ELSE = KERNEL PANIC! */
    if (version_major != 14 && version_minor != 5 && version_revision != 0)
    {
        ERROR_MSG("This kext only supports Yosemite 10.10.5.");
        return KERN_NOT_SUPPORTED;
    }

    /* initialize structure with kernel information to solve symbols */
    if (init_kernel_info() != KERN_SUCCESS)
    {
        /* in case of failure buffers are freed inside */
        ERROR_MSG("Failed to init kernel info structure!");
        return KERN_FAILURE;
    }
    
    /* solve kernel symbols we need */
    SOLVE_KERNEL_SYMBOL("_csfg_get_path", _csfg_get_path)
    SOLVE_KERNEL_SYMBOL("_csfg_get_teamid", _csfg_get_teamid)
    SOLVE_KERNEL_SYMBOL("_csfg_get_platform_binary", _csfg_get_platform_binary)
    SOLVE_KERNEL_SYMBOL("_csproc_get_teamid", _csproc_get_teamid)
    SOLVE_KERNEL_SYMBOL("_ubc_cs_blob_get", _ubc_cs_blob_get)
    
    start_trustedbsd_hooks(d);
    
    return KERN_SUCCESS;
}

kern_return_t Gatekeerper_stop(kmod_info_t *ki, void *d)
{
    stop_trustedbsd_hooks();
    return KERN_SUCCESS;
}
