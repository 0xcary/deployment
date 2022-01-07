// SPDX-License-Identifier: MIT

pragma solidity ^0.6.0;

interface INodeStaking {
    // 质押状态: 无效 未质押、已质押、锁定中、已取回
    enum StakingStage { INVALID, NOSTAKE, STAKED, LOCKING, WITHDRAWED }
    function isValidatorCandidate(address _validatorCandidate) external view returns (bool);
    function getValidatorCandidateStakingStatus(address _validatorCandidate) external view returns (bool, uint256, StakingStage, uint256, uint256, uint256);
}