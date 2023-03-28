#include <algorithm>
#include <functional>
#include <random>
#include <math.h>

#include "ll_buda/host_api.hpp"
#include "common/bfloat16.hpp"

#include "llrt/llrt.hpp"
#include "llrt/tests/test_libs/debug_mailbox.hpp"

//////////////////////////////////////////////////////////////////////////////////////////
// TODO: explain what test does
//////////////////////////////////////////////////////////////////////////////////////////
using namespace tt;

bool interleaved_stick_reader_test() {
    bool pass = true;

    try {
        ////////////////////////////////////////////////////////////////////////////
        //                      Grayskull Device Setup
        ////////////////////////////////////////////////////////////////////////////
        int pci_express_slot = 0;
        ll_buda::Device *device =
            ll_buda::CreateDevice(tt::ARCH::GRAYSKULL, pci_express_slot);

        pass &= ll_buda::InitializeDevice(device);

        ////////////////////////////////////////////////////////////////////////////
        //                      Application Setup
        ////////////////////////////////////////////////////////////////////////////
        ll_buda::Program *program = new ll_buda::Program();

        auto num_cores_c = 2;
        auto num_cores_r = 2;
        tt_xy_pair start_core = {0, 0};
        tt_xy_pair end_core = {(std::size_t)num_cores_c - 1, (std::size_t)num_cores_r - 1};;
        ll_buda::CoreRange all_cores(start_core, end_core);

        int num_sticks = 4;
        int num_elements_in_stick = 512;
        int stick_size = num_elements_in_stick * 2;
        int num_elements_in_stick_as_packed_uint32 = num_elements_in_stick / 2;

        uint32_t dram_buffer_size =  num_sticks * stick_size; // num_tiles of FP16_B, hard-coded in the reader/writer kernels

        uint32_t dram_buffer_src_addr = 0;
        int dram_src_channel_id = 0;

        uint32_t l1_buffer_addr = 400 * 1024;
        assert(dram_buffer_size % (num_cores_r * num_cores_c) == 0);
        uint32_t per_core_l1_size = dram_buffer_size / (num_cores_r * num_cores_c);
        for(int i = 0; i < num_cores_r; i++) {
            for(int j = 0; j < num_cores_c; j++) {
                int core_index = i * num_cores_c + j;
                tt_xy_pair core = {(std::size_t) j, (std::size_t) i};
                auto l1_b0 = ll_buda::CreateL1Buffer(program, device, core, per_core_l1_size, l1_buffer_addr);
            }
        }
        auto unary_reader_kernel = ll_buda::CreateDataMovementKernel(
                                            program,
                                            "kernels/dataflow/dram_copy_stick_layout_8bank_partitioned.cpp",
                                            all_cores,
                                            ll_buda::InitializeCompileTimeDataMovementKernelArgs(all_cores, {1}),
                                            ll_buda::DataMovementProcessor::RISCV_1,
                                            ll_buda::NOC::RISCV_1_default);

        ////////////////////////////////////////////////////////////////////////////
        //                      Compile Application
        ////////////////////////////////////////////////////////////////////////////
        bool profile_kernel = true;
        pass &= ll_buda::CompileProgram(device, program, profile_kernel);

        ////////////////////////////////////////////////////////////////////////////
        //                      Execute Application
        ////////////////////////////////////////////////////////////////////////////
        std::vector<uint32_t> src_vec = create_arange_vector_of_bfloat16(
            dram_buffer_size, false);

        pass &= ll_buda::WriteToDeviceDRAMChannelsInterleaved(
            device, src_vec, dram_buffer_src_addr, num_sticks, num_elements_in_stick_as_packed_uint32, 4);
        pass &= ll_buda::ConfigureDeviceWithProgram(device, program, profile_kernel);
         std::cout << "Num cores " << num_cores_r * num_cores_c << std::endl;
        for(int i = 0; i < num_cores_r; i++) {
            for(int j = 0; j < num_cores_c; j++) {
                int core_index = i * num_cores_c + j;
                tt_xy_pair core = {(std::size_t) j, (std::size_t) i};
                ll_buda::WriteRuntimeArgsToDevice(
                    device,
                    unary_reader_kernel,
                    core,
                    {dram_buffer_src_addr,
                    (uint32_t) 1,
                    (uint32_t) stick_size,
                    (uint32_t) log2(stick_size),
                    (uint32_t) l1_buffer_addr,
                    (uint32_t) i * num_cores_c + j});
            }
        }
        pass &= ll_buda::LaunchKernels(device, program);
        ////////////////////////////////////////////////////////////////////////////
        //                      Validation & Teardown
        ////////////////////////////////////////////////////////////////////////////

        //pass &= (src_vec == result_vec);

        pass &= ll_buda::CloseDevice(device);

    } catch (const std::exception &e) {
        pass = false;
        // Capture the exception error message
        log_error(LogTest, "{}", e.what());
        // Capture system call errors that may have returned from driver/kernel
        log_error(LogTest, "System error message: {}", std::strerror(errno));
    }

    return pass;
}

int main(int argc, char **argv) {
    bool pass = true;

    //pass &= test_write_interleaved_sticks_and_then_read_interleaved_sticks();
    //pass &= interleaved_stick_reader_single_bank_tilized_writer_datacopy_test();
    //pass &= interleaved_tilized_reader_interleaved_stick_writer_datacopy_test();
    pass &= interleaved_stick_reader_test();
    if (pass) {
        log_info(LogTest, "Test Passed");
    } else {
        log_fatal(LogTest, "Test Failed");
    }
}
