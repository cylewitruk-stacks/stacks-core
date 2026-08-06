use stacks_primitives::StacksEpochId;

pub trait ClarityEpochRules {
    fn analysis_memory(self) -> bool;
    fn value_sanitizing(self) -> bool;
    fn sanitize_in_function_invocation(self) -> bool;
    fn supports_specific_budget_extends(self) -> bool;
    fn treats_unexpected_serialization_as_none(self) -> bool;
    fn rejects_supertype_too_large(self) -> bool;
    fn rejects_parse_depth_errors(self) -> bool;
    fn uses_pre_sanitized_variables(self) -> bool;
    fn clarity_uses_tip_burn_block(self) -> bool;
    fn includes_sip_031(self) -> bool;
    fn uses_marfed_block_time(self) -> bool;
    fn uses_arg_size_for_cost(self) -> bool;
    fn limits_parameter_and_method_count(self) -> bool;
    fn meters_in_contract_trait_entry(self) -> bool;
    fn handles_with_stx_combined_check(self) -> bool;
    fn sums_stacking_assetmap(self) -> bool;
    fn fixes_tuple_merge_size_check(self) -> bool;
    fn supports_call_with_constant(self) -> bool;
    fn supports_at_block(self) -> bool;
    fn fixes_map_off_by_one(self) -> bool;
    fn surfaces_trait_compliance_cost_errors(self) -> bool;
}

impl ClarityEpochRules for StacksEpochId {
    fn analysis_memory(self) -> bool {
        self >= StacksEpochId::Epoch25
    }

    fn value_sanitizing(self) -> bool {
        self >= StacksEpochId::Epoch24
    }

    fn sanitize_in_function_invocation(self) -> bool {
        self >= StacksEpochId::Epoch40
    }

    fn supports_specific_budget_extends(self) -> bool {
        self >= StacksEpochId::Epoch33
    }

    fn treats_unexpected_serialization_as_none(self) -> bool {
        self >= StacksEpochId::Epoch34
    }

    fn rejects_supertype_too_large(self) -> bool {
        self < StacksEpochId::Epoch34
    }

    fn rejects_parse_depth_errors(self) -> bool {
        self < StacksEpochId::Epoch34
    }

    fn uses_pre_sanitized_variables(self) -> bool {
        self >= StacksEpochId::Epoch34
    }

    fn clarity_uses_tip_burn_block(self) -> bool {
        self >= StacksEpochId::Epoch30
    }

    fn includes_sip_031(self) -> bool {
        self >= StacksEpochId::Epoch32
    }

    fn uses_marfed_block_time(self) -> bool {
        self >= StacksEpochId::Epoch33
    }

    fn uses_arg_size_for_cost(self) -> bool {
        self >= StacksEpochId::Epoch33
    }

    fn limits_parameter_and_method_count(self) -> bool {
        self >= StacksEpochId::Epoch33
    }

    fn meters_in_contract_trait_entry(self) -> bool {
        self >= StacksEpochId::Epoch40
    }

    fn handles_with_stx_combined_check(self) -> bool {
        self >= StacksEpochId::Epoch34
    }

    fn sums_stacking_assetmap(self) -> bool {
        self >= StacksEpochId::Epoch40
    }

    fn fixes_tuple_merge_size_check(self) -> bool {
        self >= StacksEpochId::Epoch40
    }

    fn supports_call_with_constant(self) -> bool {
        self >= StacksEpochId::Epoch34
    }

    fn supports_at_block(self) -> bool {
        self < StacksEpochId::Epoch34
    }

    fn fixes_map_off_by_one(self) -> bool {
        self >= StacksEpochId::Epoch40
    }

    fn surfaces_trait_compliance_cost_errors(self) -> bool {
        self >= StacksEpochId::Epoch40
    }
}
