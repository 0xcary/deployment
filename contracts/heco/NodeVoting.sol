// SPDX-License-Identifier: MIT

pragma solidity 0.6.9;
pragma experimental ABIEncoderV2;

import { AccessControlUpgradeSafe } from "@openzeppelin/contracts-ethereum-package/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts-ethereum-package/contracts/utils/Address.sol";
import "@openzeppelin/contracts-ethereum-package/contracts/utils/EnumerableSet.sol";
import "@openzeppelin/contracts-ethereum-package/contracts/math/SafeMath.sol";
import { OwnableUpgradeSafe } from "@openzeppelin/contracts-ethereum-package/contracts/access/Ownable.sol";
import { ReentrancyGuardUpgradeSafe } from "@openzeppelin/contracts-ethereum-package/contracts/utils/ReentrancyGuard.sol";
import './interfaces/INodeStaking.sol';
// NoteVoting is the master of HT.
//
// Have fun reading it. Hopefully it's bug-free. God bless.
contract NodeVoting is ReentrancyGuardUpgradeSafe, OwnableUpgradeSafe, AccessControlUpgradeSafe {
    using SafeMath for uint256;
    //using SafeERC20 for IERC20;
    using Address for address;
    using EnumerableSet for EnumerableSet.UintSet;
    //
    // CONSTANT
    //
    // apply to calculate fee distribution.
    uint256 public constant FEE_TOTAL_SHARES = 10000;
    uint256 public constant MAX_FEE_SHARES = 3000;

    uint256 public constant VOTE_UNIT = 1e18;

    //
    // EVENTS
    //
    event SetAccountant(address indexed accountant);
    event SetRevokeLockingDuration(uint256 duration);
    event SetFeeSetLockingDuration(uint256 duration);
    event AddValidatorPool(address indexed user, uint256 indexed pid, uint256 feeShares);
    event SetPoolEnabled(uint256 indexed pid, bool enabled);
    event SetFeeShares(address indexed user, uint256 indexed pid, uint256 shares);
    event NotifyReward(address indexed user, uint256 reward1, uint256 reward2);
    event NotifyRewardSummary(uint256 inputLength, uint256 okLength);
    event Vote(address indexed user, uint256 indexed pid, uint256 amount);
    event Revoke(address indexed user, uint256 indexed pid, uint256 amount, uint256 lockingEndTime);
    event Withdraw(address indexed user, uint256 indexed pid, uint256 amount);
    event ClaimReward(address indexed user, uint256 indexed pid, uint256 pendingReward);
    event ClaimFeeReward(address indexed validator, uint256 indexed pid, uint256 feeReward);
    event RewardTransfer(address indexed from, address indexed to, uint256 amount);


    //
    // STRUCT and Enum
    //
    // Info of each user.
    struct UserInfo {
        uint256 amount; // How many ballot tokens the user has provided.
        uint256 rewardDebt; // Reward debt.
    }
    // Info of each pool.
    struct PoolInfo {
        address validator;   // Address of validator.
        uint256 feeShares;   // 节点扣除部分的fee shares
        uint256 pendingFee;  // 节点可领取的从奖励中扣除的部分
        uint256 feeDebt;     // 记录节点从费用扣除中获得奖励总额
        uint256 lastRewardBlock;        // 最近一次奖励更新发生的块高
        uint256 feeSettLockingEndTime;  // 记录节点分成比例设置的锁定期，24小时可修改一次
        uint256 ballotSupply;
        uint256 accRewardPerShare; // Accumulated HTs per share, times 1e12. See below.
        bool enabled;        // 是否启用，默认启用
        uint256 voterNumber;
        uint256 electedNumber;
    }

    // Info of each pool.
    struct VotingData {
        address validator;          // 验证人节点地址
        uint256 pid;                // 节点投票质押池ID
        uint256 validatorBallot;    // 验证人票数
        uint256 feeShares;          // 节点分成份额
        uint256 ballot;             // 我的投票数
        uint256 pendingReward;          // 可领取奖励
        uint256 revokingBallot;         // 正在撤回的投票数
        uint256 revokeLockingEndTime;   // 撤回投票的锁定时间
    }


    // 节点质押池状态，无效 ｜ 有效
    enum PoolStatus { INVALID, VALID }

    // 投票撤销状态: 锁定中 ｜ 已经赎回
    enum RevokingStatus { LOCKING, WITHDRAWED }

    // 选票撤回的状态
    struct RevokingInfo {
        // 撤销投票HT数量
        uint256 amount;
        // 状态, 初始状态为锁定中
        RevokingStatus status;
        // 锁定结束时间
        uint256 lockingEndTime;
    }

    //**********************************************************//
    //    Can not change the order of below state variables     //
    //**********************************************************//

    // 第二阶段白名单节点质押合约
    INodeStaking public nodeStaking;

    // 总的票数
    uint256 public totalBallot;

    // 投票撤销的锁定期, 默认3天
    uint256 public revokeLockingDuration;

    // 节点费率变更的锁定期, 默认1天
    uint256 public feeSetLockingDuration;

    // 验证人地址名单，用于去重过滤
    // EnumerableSet.AddressSet private _validators;

    // 记录validator地址与下标的对应关系，方便快速定位
    mapping(address => uint256) private validatorIndexMap;

    // Info of each pool.
    PoolInfo[] public poolInfo;
    // Info of each user that stakes LP tokens.
    mapping(uint256 => mapping(address => UserInfo)) public userInfo;

    // 用户投票的撤销记录.
    mapping(address => mapping(uint256 => RevokingInfo)) public revokingInfo;

    // 用户正在参与投票活动的目标质押池pid列表.
    mapping(address => EnumerableSet.UintSet) private votingRecordIndexInfo;

    //**********************************************************//
    //    Can not change the order of above state variables     //
    //**********************************************************//

    //◥◤◥◤◥◤◥◤◥◤◥◤◥◤◥◤ add state variables below ◥◤◥◤◥◤◥◤◥◤◥◤◥◤◥◤//
    bytes32 public constant ACCOUNTANT_ROLE = keccak256("ACCOUNTANT_ROLE");

    //◢◣◢◣◢◣◢◣◢◣◢◣◢◣◢◣ add state variables above ◢◣◢◣◢◣◢◣◢◣◢◣◢◣◢◣//

    function initialize(
        address _nodeStaking,
        uint256 _revokeLockingDuration,
        uint256 _feeSetLockingDuration
    ) external initializer {
        __Ownable_init();
        __ReentrancyGuard_init();

        require(_nodeStaking != address(0), "NodeVoting: ZERO_ADDRESS.");

        nodeStaking = INodeStaking(_nodeStaking);

        // 锁定周期
        revokeLockingDuration = _revokeLockingDuration;
        feeSetLockingDuration = _feeSetLockingDuration;
        // 赋予deployer以ADMIN_Role角色
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    //
    // FUNCTIONS Write
    //

    // 授予目标地址会计角色，会计角色的账户可以调用奖励发放接口
    function grantAccountant(address _accountant) external onlyOwner {
        require(!hasRole(ACCOUNTANT_ROLE, _accountant), "NodeVoting: address has been an accountant.");

        grantRole(ACCOUNTANT_ROLE, _accountant);
    }

    // 撤销目标地址的会计角色
    function revokeAccountant(address _accountant) external onlyOwner {
        require(hasRole(ACCOUNTANT_ROLE, _accountant), "NodeVoting: address is not an accountant.");

        revokeRole(ACCOUNTANT_ROLE, _accountant);
    }

    // 设置投票撤回后的锁定周期
    function setRevokeLockingDuration(uint256 _lockingDuration) external onlyOwner {
        require(_lockingDuration != revokeLockingDuration, "NodeVoting: No change detected.");

        revokeLockingDuration = _lockingDuration;
        emit SetRevokeLockingDuration(_lockingDuration);
    }

    // 设置节点分成比例修改的锁定周期
    function setFeeSetLockingDuration(uint256 _lockingDuration) external onlyOwner {
        require(_lockingDuration != feeSetLockingDuration, "NodeVoting: No change detected.");

        feeSetLockingDuration = _lockingDuration;
        emit SetFeeSetLockingDuration(_lockingDuration);
    }

    // Add a new validator to the pools. Can only be called by the contract owner.
    function addValidatorPool(address _validator, uint256 _feeShares) public onlyOwner {
        require(_validator != address(0), "NodeVoting: ZERO_ADDRESS.");
        require(_feeShares <= MAX_FEE_SHARES, "NodeVoting: the fee shares should be in the range(0..3000).");

        // 获取验证人地址对应的投票质押池id的索引值
        uint256 pidIndex = validatorIndexMap[_validator];

        require(pidIndex == 0, "NodeVoting: Duplicated validator Address.");

        INodeStaking.StakingStage status;
        (,,status,,,) = nodeStaking.getValidatorCandidateStakingStatus(_validator);

        require(status == INodeStaking.StakingStage.STAKED, "NodeVoting: invalid staking status.");

        // 增加新validator投票质押池
        poolInfo.push(
            PoolInfo({
        validator: _validator,
        feeShares: _feeShares,
        lastRewardBlock: block.number,
        feeSettLockingEndTime: block.timestamp.add(feeSetLockingDuration),
        pendingFee: 0,
        feeDebt: 0,
        ballotSupply: 0,
        accRewardPerShare: 0,
        enabled: true,
        voterNumber: 0,
        electedNumber: 0
        })
        );
        // 添加质押池pid索引值进索引Map
        validatorIndexMap[_validator] = poolInfo.length;
        // 获取质押池pid: 索引值减去1
        uint256 pid = validatorIndexMap[_validator].sub(1);

        // emit event
        emit AddValidatorPool(_validator, pid,  _feeShares);
    }

    // Enable/disable the target pool. Can only be called by the pool owner.
    function setPoolEnabled(
        uint256 _pid,
        bool _enabled
    ) public onlyOwner {
        PoolInfo storage pool = poolInfo[_pid];
        require(pool.enabled != _enabled, "NodeVoting: No Change detected.");

        pool.enabled = _enabled;

        // emit event
        emit SetPoolEnabled(_pid, _enabled);
    }

    // Update the given pool's validator reward allocation ratio. Can only be called by the pool owner.
    function setFeeSharesOfValidator(
        uint256 _shares
    ) public {
        // 获取验证人地址对应的投票质押池id的索引值
        uint256 pidIndex = validatorIndexMap[msg.sender];

        require(pidIndex != 0, "NodeVoting: validator does not exist.");

        uint256 pid = pidIndex.sub(1);

        require(poolInfo[pid].validator == msg.sender, "NodeVoting: only pool owner can update the fee shares.");
        require(_shares <= MAX_FEE_SHARES, "NodeVoting: the fee shares should be in the range(0..3000).");
        require(block.timestamp >= poolInfo[pid].feeSettLockingEndTime, "NodeVoting: one time of change within 24 hours.");

        PoolInfo storage pool = poolInfo[pid];

        require(_shares != pool.feeShares, "NodeVoting: no change detected.");

        // total 10000(1e4) shares, how many shares validator itself occupies.
        pool.feeShares = _shares;
        // 更新lockingTime
        pool.feeSettLockingEndTime = block.timestamp.add(feeSetLockingDuration);

        // emit event
        emit SetFeeShares(msg.sender, pid, _shares);
    }

    // Update reward variables of the given pool to be up-to-date.
    function notifyRewardAmount(address[] calldata _validators, uint256[] calldata _rewardAmounts) external payable nonReentrant() {
        require(hasRole(ACCOUNTANT_ROLE, msg.sender), "NodeVoting: the caller is not an accountant.");
        require(_validators.length > 0 && _rewardAmounts.length > 0, "NodeVoting: both input arrays can't be empty.");
        require(_validators.length == _rewardAmounts.length, "NodeVoting: two input arrays' length must be the same.");
        require(_validators.length <= 30 && _rewardAmounts.length <= 30, "NodeVoting: max 30 elements in array!");

        uint256 length = _validators.length;
        uint256 totalReward = 0;
        uint256 okCounter = 0;

        for(uint i = 0; i < _validators.length; i++) {
            address validator = _validators[i];
            // 是否存在对应的节点质押池
            if(validatorIndexMap[validator] != 0) {
                // get validator pool id - pid by address
                uint256 pid = validatorIndexMap[validator].sub(1);

                PoolInfo storage pool = poolInfo[pid];
                uint256 ballotSupply = pool.ballotSupply;
                uint256 feeShares = pool.feeShares;

                uint256 rewardAmount = _rewardAmounts[i];

                // 计算节点扣除的部分奖励
                uint256 feeReward = rewardAmount.mul(feeShares).div(FEE_TOTAL_SHARES);

                // 更新节点费用扣除累积的奖励
                pool.pendingFee = pool.pendingFee.add(feeReward);
                pool.lastRewardBlock = block.number;
                // 更新节点当选次数
                pool.electedNumber = pool.electedNumber.add(1);

                // 扣除节点自身收取的那部分，剩下的奖励分给投票质押的用户
                // reward to be distributed to staked users
                uint256 votingReward = rewardAmount.sub(feeReward);

                // 更新计数
                okCounter = okCounter.add(1);

                // 跳过质押投票数目为0的质押投票池
                if(ballotSupply == 0) {
                    // counting payable total reward
                    totalReward = totalReward.add(feeReward);
                    continue;
                } else {
                    // 计算每个vote可分到的reward数量
                    pool.accRewardPerShare = pool.accRewardPerShare.add(votingReward.mul(1e12).div(pool.ballotSupply));
                }
                // counting payable total reward
                totalReward = totalReward.add(rewardAmount);
                // emit multiple events
                emit NotifyReward(validator, feeReward, votingReward);
            }
        }

        require(msg.value >= totalReward, "NodeVoting: input value is less than the total reward value.");

        // 获取发送奖励与应付之间的差值
        uint256 diff = msg.value.sub(totalReward);

        //return back the extra amount
        // 大于0返还
        if(diff > 0) {
            _msgSender().transfer(diff);
        }

        // 通知输入多少个，处理了多少个，成功处理的下标列表
        emit NotifyRewardSummary(length, okCounter);
    }

    // Deposit ballot - HT to the target validator for Reward allocation.
    function vote(uint256 _pid) public payable nonReentrant() {
        uint256 ballotAmount = msg.value.div(VOTE_UNIT);

        // 票数必须是1HT的整数倍
        require(msg.value > 0 && ballotAmount > 0, "NodeVoting: votes must be integer multiple of 1 HT.");

        uint256 ballotValue = ballotAmount.mul(VOTE_UNIT);
        uint256 diff = msg.value.sub(ballotValue);

        if(diff > 0) {
            _msgSender().transfer(diff); // 多余的退回
        }

        _vote(msg.sender, _pid, ballotValue);
    }

    // Withdraw vote tokens from target pool.
    function revokeVote(uint256 _pid, uint256 _amount) external nonReentrant() {
        _revokeVote(msg.sender, _pid, _amount);
    }

    function withdraw(uint _pid) external nonReentrant() {
        require(_isWithdrawable(msg.sender, _pid), "NodeVoting: no ballots to withdraw or ballots are still locking.");

        _withdraw(msg.sender, _pid);
    }

    // claim reward tokens from target pool.
    function claimReward(uint256 _pid) external nonReentrant() {
        UserInfo storage user = userInfo[_pid][msg.sender];
        // 计算并将奖励发送给用户
        uint256 pending = _calculatePendingReward(_pid, msg.sender);
        require(pending > 0, "NodeVoting: no pending reward to claim.");

        _safeRewardTransfer(pending);
        // 更新已经领取的奖励
        user.rewardDebt = user.amount.mul(poolInfo[_pid].accRewardPerShare).div(1e12);
        emit ClaimReward(msg.sender, _pid, pending);
    }

    // validator提取自身奖励
    function claimFeeReward() external nonReentrant() {
        uint256 pid = validatorIndexMap[msg.sender].sub(1);

        PoolInfo storage pool = poolInfo[pid];
        address validator = pool.validator;
        uint256 feeReward = pool.pendingFee;
        require(validator == msg.sender, "NodeVoting: only validator itself can collect his fee reward.");

        require(feeReward > 0, "NodeVoting: no pending fee reward to claim.");

        pool.pendingFee = 0; // reset to 0
        pool.feeDebt = pool.feeDebt.add(feeReward);

        // 将奖励发送至节点用户
        msg.sender.transfer(feeReward);
        emit ClaimFeeReward(validator, pid, feeReward);
    }


    //
    // FUNCTIONS Readonly
    //

    // get pool length
    function getPoolLength() external view returns (uint256) {
        return poolInfo.length;
    }

    // 判断地址是否是会计账户
    function isAccountant(address _accountant) external view returns (bool) {
        return hasRole(ACCOUNTANT_ROLE, _accountant);
    }

    // 获取拥有会计角色的账户数量
    function getAccountantLength() external view returns (uint256) {
        return getRoleMemberCount(ACCOUNTANT_ROLE);
    }

    // 获取拥有会计角色的账户数量
    function getAccountant(uint256 _index) external view returns (address) {
        return getRoleMember(ACCOUNTANT_ROLE, _index);
    }

    // 判断一个地址是否是验证人pool
    function isPool(address _validator) external view returns (bool) {
        return (validatorIndexMap[_validator] != 0);
    }

    // 返回下标对应的质押池基本信息以及节点质押状态决定的质押池状态
    function getPoolWithStatus(uint256 _pid) external view returns (address, uint256, uint256, uint256, uint256, uint256, uint256, uint256, bool, uint256, uint256, PoolStatus) {
        PoolInfo memory pool = poolInfo[_pid];
        INodeStaking.StakingStage status;
        (,,status,,,) = nodeStaking.getValidatorCandidateStakingStatus(pool.validator);

        PoolStatus poolStatus = PoolStatus.VALID;
        if(status != INodeStaking.StakingStage.STAKED) {
            poolStatus = PoolStatus.INVALID;
        }
        return (pool.validator, pool.feeShares, pool.pendingFee, pool.feeDebt, pool.lastRewardBlock, pool.feeSettLockingEndTime,
        pool.ballotSupply, pool.accRewardPerShare, pool.enabled, pool.voterNumber, pool.electedNumber, poolStatus);
    }

    // 获取用户投票给目标节点产生的可领取奖励
    function pendingReward(uint256 _pid, address _user)
    external
    view
    returns (uint256)
    {
        return _calculatePendingReward(_pid, _user);
    }

    // 获取用户投票质押产生的所有可领取奖励
    function getUserVotingSummary(address _user)
    external
    view
    returns (VotingData[] memory votingDataList)
    {
        EnumerableSet.UintSet storage recordIndexes = votingRecordIndexInfo[_user];

        uint256 recordIndexesLength = EnumerableSet.length(recordIndexes);
        votingDataList = new VotingData[](recordIndexesLength);


        uint256 index = 0;
        for(uint i = 0; i < recordIndexesLength; i++) {
            uint256 pid = EnumerableSet.at(recordIndexes, i);

            PoolInfo memory pool = poolInfo[pid];
            UserInfo memory user = userInfo[pid][_user];
            RevokingInfo memory revokingInfoItem = revokingInfo[_user][pid];

            uint256 pending = _calculatePendingReward(pid, _user);
            votingDataList[index] = VotingData({
            validator: pool.validator,
            pid: pid,
            validatorBallot: pool.ballotSupply,
            feeShares: pool.feeShares,
            ballot: user.amount,
            pendingReward: pending,
            revokingBallot: revokingInfoItem.amount,
            revokeLockingEndTime: revokingInfoItem.lockingEndTime
            });
            index = index.add(1);
        }
    }

    // 获取节点自身可领取的奖励
    function pendingFeeReward(address _validator)
    external
    view
    returns (uint256)
    {
        require(validatorIndexMap[_validator] != 0, "NodeVoting: invalid validator address.");
        uint256 pid = validatorIndexMap[_validator].sub(1);
        PoolInfo memory pool = poolInfo[pid];
        return pool.pendingFee;
    }

    // 目标用户当前质押池锁定部分是否可以取回
    function _isWithdrawable(address _user, uint256 _pid) public view returns (bool) {
        RevokingInfo memory revokingInfoItem = revokingInfo[_user][_pid];
        return (revokingInfoItem.amount > 0 && revokingInfoItem.status == RevokingStatus.LOCKING && block.timestamp >= revokingInfoItem.lockingEndTime);
    }

    function _calculatePendingReward(uint256 _pid, address _user) internal view returns(uint) {
        PoolInfo memory pool = poolInfo[_pid];
        UserInfo memory user = userInfo[_pid][_user];

        return user.amount.mul(pool.accRewardPerShare).div(1e12).sub(user.rewardDebt);
    }

    function _vote(address _user, uint256 _pid, uint256 _amount) internal {
        PoolInfo storage pool = poolInfo[_pid];
        require(pool.enabled == true, "NodeVoting: pool is disabled.");

        INodeStaking.StakingStage status;
        (,,status,,,) = nodeStaking.getValidatorCandidateStakingStatus(pool.validator);

        require(status == INodeStaking.StakingStage.STAKED, "NodeVoting: invalid staking status.");

        UserInfo storage user = userInfo[_pid][_user];

        // 计算并领取奖励
        if (user.amount > 0) {
            // 计算并将奖励发送给用户
            uint256 pending = _calculatePendingReward(_pid, _user);
            if(pending > 0) {
                _safeRewardTransfer(pending);
                emit ClaimReward(_user, _pid, pending);
            }
        } else {
            // 用户首次或者再次从0给当前节点质押池投票
            // 更新节点质押池投票地址数目
            pool.voterNumber = pool.voterNumber.add(1);

            EnumerableSet.UintSet storage recordIndexes = votingRecordIndexInfo[_user];
            EnumerableSet.add(recordIndexes, _pid);
        }
        // 更新用户质押的数量
        user.amount = user.amount.add(_amount);
        // 更新已经领取的奖励
        user.rewardDebt = user.amount.mul(pool.accRewardPerShare).div(1e12);
        // 更新池子总票数
        pool.ballotSupply= pool.ballotSupply.add(_amount);
        // 更新总投票数
        totalBallot = totalBallot.add(_amount);

        // emit event
        emit Vote(_user, _pid, _amount);
    }

    function _withdraw(address _user, uint256 _pid) internal {
        RevokingInfo storage revokingInfoItem = revokingInfo[_user][_pid];
        UserInfo memory user = userInfo[_pid][_user];

        uint256 amount = revokingInfoItem.amount;
        // 将状态设为已赎回
        revokingInfoItem.status = RevokingStatus.WITHDRAWED;
        // 将数量重置为0
        revokingInfoItem.amount = 0;
        // 将撤回的HT投票发送至投票人
        msg.sender.transfer(amount);

        // 用户已经全部撤回并赎回所有投票
        if(user.amount == 0) {
            EnumerableSet.UintSet storage recordIndexes = votingRecordIndexInfo[_user];
            // 移除目标投票质押池pid
            EnumerableSet.remove(recordIndexes, _pid);
        }
        emit Withdraw(_user, _pid, amount);
    }

    function _revokeVote(address _user, uint256 _pid, uint256 _amount) internal {
        require(_amount > 0 && _amount.mod(VOTE_UNIT) == 0, "NodeVoting: votes must be integer multiple of 1 HT.");

        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][_user];
        RevokingInfo storage revokingInfoItem = revokingInfo[_user][_pid];

        uint256 availableAmount = user.amount;
        require(availableAmount >= _amount, "NodeVoting: no enough ballots to revoke.");

        // 计算并将奖励发送给用户
        uint256 pending = _calculatePendingReward(_pid, _user);

        if(pending > 0) {
            _safeRewardTransfer(pending);
            emit ClaimReward(_user, _pid, pending);
        }

        // 取回可以赎回的已撤销的投票
        if(_isWithdrawable(_user, _pid)) {
            _withdraw(_user, _pid);
        }
        // 池子票数减少
        pool.ballotSupply = pool.ballotSupply.sub(_amount);
        // 用户该池子选票减少
        user.amount = availableAmount.sub(_amount);
        // 更新已经领取的奖励
        user.rewardDebt = user.amount.mul(pool.accRewardPerShare).div(1e12);
        // 更新总投票数
        totalBallot = totalBallot.sub(_amount);

        if(user.amount == 0) {
            // 用户已经全部撤回选票
            // 更新选民地址数目
            pool.voterNumber = pool.voterNumber.sub(1);
        }
        uint256 lastAmount = revokingInfoItem.amount;
        // 还有未提取的锁定奖励
        if(lastAmount > 0) {
            uint256 lastLockingEndTime = revokingInfoItem.lockingEndTime;
            uint256 lastLeftLockingTime = lastLockingEndTime.sub(block.timestamp);

            uint256 totalAmount = lastAmount.add(_amount);
            uint256 newAmountShare = _amount.mul(revokeLockingDuration);
            uint256 avgLockingTime = lastAmount.mul(lastLeftLockingTime).add(newAmountShare).div(totalAmount);

            // 更新数量和状态
            revokingInfoItem.amount = totalAmount;
            revokingInfoItem.status = RevokingStatus.LOCKING;
            // 锁定结束时间 = 当前时间戳 + 加权平均后的锁定时间
            revokingInfoItem.lockingEndTime = block.timestamp.add(avgLockingTime);
        } else {
            // 更新数量和状态
            revokingInfoItem.amount = _amount;
            revokingInfoItem.status = RevokingStatus.LOCKING;
            // 锁定结束时间 = 当前时间戳 + 默认3天
            revokingInfoItem.lockingEndTime = block.timestamp.add(revokeLockingDuration);
        }

        // emit event
        emit Revoke(_user, _pid, revokingInfoItem.amount, revokingInfoItem.lockingEndTime);
    }

    function _safeRewardTransfer(uint256 _reward) internal {
        uint256 totalSpendableReward = address(this).balance;
        if(_reward > totalSpendableReward) {
            // 将奖励转给用户地址
            msg.sender.transfer(totalSpendableReward);
            emit RewardTransfer(address(this), msg.sender, totalSpendableReward);
        } else {
            // 将奖励转给用户地址
            msg.sender.transfer(_reward);
            emit RewardTransfer(address(this), msg.sender, _reward);
        }
    }
}