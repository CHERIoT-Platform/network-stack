// Copyright The Good Penguin Ltd
// SPDX-License-Identifier: MIT
// Combined wolfCrypt test and benchmark for CHERIoT.
// Compile with -DRUN_TEST and/or -DRUN_BENCH to select what runs.
// If both are enabled, the test suite runs first.

#include <wolfssl/wolfcrypt/settings.h>

#if !defined(RUN_TEST) && !defined(RUN_BENCH)
#error "At least one of run_test or run_bench must be enabled via xmake options"
#endif

#ifdef RUN_TEST
#include <wolfcrypt/test/test.h>
#endif
#ifdef RUN_BENCH
#include <wolfcrypt/benchmark/benchmark.h>
#endif

#include <allocator.h>
#include <cheri.hh>
#include <compartment.h>
#include <debug.hh>
#include <priv/riscv.h>
#include <stdio.h>
#include <thread.h>
#include <tick_macros.h>
#include "../../../lib/wolfssl/wolfssl_glue.h"

using Debug = ConditionalDebug<true, "WolfCrypt">;

#ifdef RUN_BENCH
// benchmark.c measures wall time so stub here for that based on cpu cycles
extern "C" double current_time(int reset)
{
    return (double)rdcycle64() / (double)CPU_TIMER_HZ;
}
#endif

extern "C" ErrorRecoveryBehaviour
compartment_error_handler(ErrorState *frame, size_t mcause, size_t mtval)
{
    if (mcause == priv::MCAUSE_CHERI)
    {
        auto [exceptionCode, registerNumber] =
          CHERI::extract_cheri_mtval(mtval);
        Debug::log("CHERI fault: {} at {} register {}: {}",
                   exceptionCode,
                   frame->pcc,
                   registerNumber,
                   registerNumber == CHERI::RegisterNumber::CZR
                     ? nullptr
                     : *frame->get_register_value(registerNumber));
    }
    else
    {
        Debug::log("Fault mcause={} at {}", mcause, frame->pcc);
    }
    return ErrorRecoveryBehaviour::ForceUnwind;
}

DECLARE_AND_DEFINE_ALLOCATOR_CAPABILITY(WolfCryptHeap, 64 * 1024);
#define WOLFCRYPT_HEAP STATIC_SEALED_VALUE(WolfCryptHeap)

void __cheri_compartment("wolfcrypt") heartbeat_main()
{
    uint32_t elapsed_s = 0;
    while (true)
    {
        Timeout t = {0, MS_TO_TICKS(5000)};
        thread_sleep(&t, ThreadSleepNoEarlyWake);
        elapsed_s += 5;
        printf("[%4us] still running...\n", elapsed_s);
    }
}

void __cheri_compartment("wolfcrypt") combined_main()
{
    wolfssl_set_fallback_heap((void *)WOLFCRYPT_HEAP);

#ifdef RUN_TEST
    Debug::log("=== wolfCrypt test suite ===");
    wc_test_ret_t tret = wolfcrypt_test(NULL);
    if (tret == 0)
    {
        Debug::log("=== ALL TESTS PASSED ===");
    }
    else
    {
        Debug::log("=== TESTS FAILED: ret={} ===", static_cast<int>(tret));
    }
#endif

#ifdef RUN_BENCH
    Debug::log("=== wolfCrypt benchmark suite ===");
    int bret = benchmark_test(NULL);
    if (bret == 0)
    {
        Debug::log("=== BENCHMARK COMPLETE ===");
    }
    else
    {
        Debug::log("=== BENCHMARK FAILED: ret={} ===", bret);
    }
#endif
}
