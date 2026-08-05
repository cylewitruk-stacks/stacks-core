use stacks_primitives::StacksEpochId;

pub trait ClarityEpochRules {
    fn analysis_memory(self) -> bool;
    fn value_sanitizing(self) -> bool;
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
    fn handles_with_stx_combined_check(self) -> bool;
    fn supports_call_with_constant(self) -> bool;
    fn supports_at_block(self) -> bool;
}

impl ClarityEpochRules for StacksEpochId {
    fn analysis_memory(self) -> bool {
        self >= StacksEpochId::Epoch25
    }

    fn value_sanitizing(self) -> bool {
        self >= StacksEpochId::Epoch24
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
        matches!(self, StacksEpochId::Epoch34)
    }

    fn clarity_uses_tip_burn_block(self) -> bool {
        self >= StacksEpochId::Epoch30
    }

    fn includes_sip_031(self) -> bool {
        matches!(
            self,
            StacksEpochId::Epoch32 | StacksEpochId::Epoch33 | StacksEpochId::Epoch34
        )
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

    fn handles_with_stx_combined_check(self) -> bool {
        self >= StacksEpochId::Epoch34
    }

    fn supports_call_with_constant(self) -> bool {
        self >= StacksEpochId::Epoch34
    }

    fn supports_at_block(self) -> bool {
        self < StacksEpochId::Epoch34
    }
}
