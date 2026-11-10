// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * Simplified IncomeContract for local testing.
 * Models the same economics as the full Intercoin IncomeContract:
 * owner registers recipients, calls pay() to credit them,
 * recipients call claim() to withdraw.
 */
contract IncomeContractDirect {
    using SafeERC20 for IERC20;

    address public owner;
    IERC20 public token;

    struct Recipient {
        uint256 paid;      // total credited by owner
        uint256 claimed;   // total withdrawn
        bool exists;
    }

    mapping(address => Recipient) public recipients;

    event RecipientAdded(address indexed recipient);
    event Paid(address indexed recipient, uint256 amount);
    event Claimed(address indexed recipient, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "NOT_OWNER");
        _;
    }

    modifier recipientExists(address r) {
        require(recipients[r].exists, "NO_SUCH_RECIPIENT");
        _;
    }

    constructor(address token_) {
        owner = msg.sender;
        token = IERC20(token_);
    }

    function addRecipient(address r) external onlyOwner {
        require(!recipients[r].exists, "ALREADY_EXISTS");
        recipients[r].exists = true;
        emit RecipientAdded(r);
    }

    /// @notice Credit `amount` to `recipient`. Tokens must already be in this contract.
    function pay(address recipient, uint256 amount) external onlyOwner recipientExists(recipient) {
        recipients[recipient].paid += amount;
        emit Paid(recipient, amount);
    }

    /// @notice Withdraw all unclaimed balance.
    function claim() external recipientExists(msg.sender) {
        Recipient storage r = recipients[msg.sender];
        uint256 available = r.paid - r.claimed;
        require(available > 0, "NOTHING_TO_CLAIM");
        r.claimed += available;
        token.safeTransfer(msg.sender, available);
        emit Claimed(msg.sender, available);
    }

    /// @notice View claimable balance.
    function claimable(address recipient) external view returns (uint256) {
        Recipient storage r = recipients[recipient];
        if (!r.exists) return 0;
        return r.paid - r.claimed;
    }
}
