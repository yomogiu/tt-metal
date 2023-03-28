#include <cstdint>

#include "compute_hlk_api.h"


struct hlk_args_t {
    std::int32_t per_core_tile_cnt;
    std::int32_t num_ops;
    std::int32_t num_repetitions;
};

void compute_main(const hlk_args_t *args) {

    // Need to pre-initialize an op_info struct and pass into get_next_op_info and modify in that func, since hlkc doesn't support funcs returning vals yet
    // TODO(AP): revisit after hlkc removal
    op_info_t op_info = {0, 0, 0, 0, 0, 0, 0};

    for (int count = 0; count < args->num_repetitions; count++) {
        for (int op_idx = 0; op_idx < args->num_ops; op_idx++) {
            hlk_get_next_op_info(core_ptr, op_info);

            for (int idx = 0; idx < args->per_core_tile_cnt; idx++) {
                cb_reserve_back(op_info.cb_out_id, 1);
                acquire_dst(DstMode::Half);
                cb_wait_front(op_info.cb_in0_id, 1);


                if (op_info.unary) {
                    copy_tile_init();
                    copy_tile(op_info.cb_in0_id, 0, 0);
                } else {
                    cb_wait_front(op_info.cb_in1_id, 1);
                }

                if (op_info.op_code == (int)OpCode::Exponential) {
                    exp_tile_init();
                    exp_tile(0);
                } else if (op_info.op_code == (int)OpCode::Reciprocal) {
                    recip_tile_init();
                    recip_tile(0);
                } else if (op_info.op_code == (int)OpCode::Gelu) {
                    gelu_tile_init();
                    gelu_tile(0);
                } else if (op_info.op_code == (int)OpCode::Add) {
                    add_tiles_init();
                    add_tiles(op_info.cb_in0_id, op_info.cb_in1_id, 0, 0, 0);
                } else if (op_info.op_code == (int)OpCode::Subtract) {
                    sub_tiles_init();
                    sub_tiles(op_info.cb_in0_id, op_info.cb_in1_id, 0, 0, 0);
                } else if (op_info.op_code == (int)OpCode::Multiply) {
                    mul_tiles_init();
                    mul_tiles(op_info.cb_in0_id, op_info.cb_in1_id, 0, 0, 0);
                }

                pack_tile(0, op_info.cb_out_id);

                if (op_info.pop0) {
                    cb_pop_front(op_info.cb_in0_id, 1);  // Don't always pop, may need the input for later
                }

                if (not op_info.unary and op_info.pop1) {
                    cb_pop_front(op_info.cb_in1_id, 1);
                }

                release_dst(DstMode::Half);
                cb_push_back(op_info.cb_out_id, 1);
            }
        }
    }
}
