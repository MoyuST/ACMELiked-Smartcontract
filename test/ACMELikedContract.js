const { loadFixture } = require("@nomicfoundation/hardhat-network-helpers")
const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("ACME-Likeded Contract", function () {
    async function deployContractFixture() {
        const CertCoordinatorFac = await ethers.getContractFactory("CertCoordinator");
        const [owner, addr1, addr2] = await ethers.getSigners();

        const CertCoordinator = await CertCoordinatorFac.deploy();

        return {CertCoordinatorFac, CertCoordinator, owner, addr1, addr2};
    }

    it("New Account Test", async function () {

        // status invalid by default
        const {CertCoordinator, addr1} = await loadFixture(deployContractFixture);
        let accountInfo = await CertCoordinator.connect(addr1).getUserInfo();
        expect(accountInfo["status"], "Account status should be invalid before registration").to.equal(0);

        // status invalid if registration without agreement of ToS
        await expect(CertCoordinator.connect(addr1).newAccount(["sample@test.com", "sample2@test.com"], false), 
            "NewAccount event should be deactivated")
            .to.emit(CertCoordinator, "NewAccountLog").withArgs(addr1.address, "deactivated");
        accountInfo = await CertCoordinator.connect(addr1).getUserInfo();
        await expect(accountInfo["status"], "Account status should be invalid without agreement of ToS").to.equal(0);
        
        // status valid if registration with agreement of ToS
        await expect(CertCoordinator.connect(addr1).newAccount(["sample@test.com", "sample2@test.com"], true),
            "NewAccount event should be created")
            .to.emit(CertCoordinator, "NewAccountLog").withArgs(addr1.address, "created");
        accountInfo = await CertCoordinator.connect(addr1).getUserInfo();
        expect(accountInfo, "Account status should be properly set")
            .to.eql([1, ["sample@test.com", "sample2@test.com"], true, []]);

        // event should be updated if exsiting user call newAccount
        await expect(CertCoordinator.connect(addr1).newAccount(["new_sample@test.com", "new_sample@test.com"], true),
            "NewAccount event should be updated")
            .to.emit(CertCoordinator, "NewAccountLog").withArgs(addr1.address, "updated");
        accountInfo = await CertCoordinator.connect(addr1).getUserInfo();
        expect(accountInfo, "Account status should be properly set")
            .to.eql([1, ["new_sample@test.com", "new_sample@test.com"], true, []]);

        // status should be invalid after user deactivate the account
        await expect(CertCoordinator.connect(addr1).newAccount([], false),
            "NewAccount event should be created")
            .to.emit(CertCoordinator, "NewAccountLog").withArgs(addr1.address, "deactivated");
        accountInfo = await CertCoordinator.connect(addr1).getUserInfo();
        expect(accountInfo["status"], "Account status should be invalid after deactivation").to.equal(0);
    });

    it("New Order Test", async function () {
        const {CertCoordinator, addr1} = await loadFixture(deployContractFixture);

        // unregitried user should be reverted
        await expect(CertCoordinator.connect(addr1).newOrder([[0, "test.com"]], 0, 604800), "unregitried user should be reverted")
            .to.be.reverted;
        
        // status valid if registration with agreement of ToS
        await expect(CertCoordinator.connect(addr1).newAccount(["sample@test.com", "sample2@test.com"], true),
            "NewAccount event should be created")
            .to.emit(CertCoordinator, "NewAccountLog").withArgs(addr1.address, "created");

        // reverted because of unsupported identification type
        await expect(CertCoordinator.connect(addr1).newOrder([[0, "test.com"], [1, "test2.com"]], 0, 604800), "unregitried user should be reverted")
            .to.be.reverted;

        // used for log checking
        let tx = await CertCoordinator.connect(addr1).newOrder([[0, "*.test.com"], [0, "test2.com"]], 0, 604800);
        let receipt = await tx.wait();
        let newOrderLogs = receipt["events"].filter(x => x["event"] === "NewOrderLog");
        expect(newOrderLogs[0]["args"], "first event is inproper").to.eql([addr1.address, ethers.BigNumber.from(0), ethers.BigNumber.from(0)]);
        expect(newOrderLogs[1]["args"], "second event is inproper").to.eql([addr1.address, ethers.BigNumber.from(0), ethers.BigNumber.from(1)]);

        let rt = await CertCoordinator.connect(addr1).getUserInfo();
        expect(rt["orders"][0]["identifiers"], "Identifier not valid").to.eql([
            [0, "test.com"],
            [0, "test2.com"],
        ]);

        expect(rt["orders"][0]["authorizations"][0]["wildcard"], "wildcard of *.test.com should be true").to.eql(true);
        expect(rt["orders"][0]["authorizations"][1]["wildcard"], "wildcard of test2.com should be false").to.eql(false);

    });

    it("Token Transfer & Withdraw Test", async function () {
        const {CertCoordinator, addr1} = await loadFixture(deployContractFixture);

        await expect(CertCoordinator.connect(addr1).tokenWithdraw(10), "withdraw 12 from unfunded account should fail").to.be.reverted;

        let tx = await CertCoordinator.onTokenTransfer(addr1.address, 10, 0x0);
        let receipt = await tx.wait();
        let onTokenTransferLogs = receipt["events"].filter(x => x["event"] === "FundsUpdate");
        expect(onTokenTransferLogs.length, "transfer should only generate one event").to.eql(1);
        expect(onTokenTransferLogs[0]["args"], "onTokenTransfer parameter not as expected").to.eql([addr1.address, ethers.BigNumber.from(10)]);

        await expect(CertCoordinator.connect(addr1).tokenWithdraw(12), "withdraw 12 from 10 token should fail").to.be.reverted;
        // await expect(CertCoordinator.connect(addr1).tokenWithdraw(-1), "withdraw uint256(-1) from 10 should fail").to.be.reverted;

        tx = await CertCoordinator.connect(addr1).tokenWithdraw(9);
        receipt = await tx.wait();
        onTokenTransferLogs = receipt["events"].filter(x => x["event"] === "FundsUpdate");
        expect(onTokenTransferLogs.length, "transfer should only generate one event").to.eql(1);
        expect(onTokenTransferLogs[0]["args"], "onTokenTransfer event parameter not as expected").to.eql([addr1.address, ethers.BigNumber.from(1)]);

    });

    it("New Challenge Test", async function (){
        const {CertCoordinator, addr1} = await loadFixture(deployContractFixture);

        await expect(CertCoordinator.connect(addr1).newChallenge(0, 0, 0), "unregistered account should be reverted").to.be.reverted;

        await expect(CertCoordinator.connect(addr1).newAccount(["sample@test.com", "sample2@test.com"], true),
            "NewAccount event should be created")
            .to.emit(CertCoordinator, "NewAccountLog").withArgs(addr1.address, "created");

        await expect(CertCoordinator.connect(addr1).newChallenge(0, 0, 0), "not sufficient funds should be reverted").to.be.reverted;        
        await CertCoordinator.onTokenTransfer(addr1.address, 10, 0x0);

        await expect(CertCoordinator.connect(addr1).newChallenge(0, 0, 3), "inproper challenge type should be reverted").to.be.reverted;
        await expect(CertCoordinator.connect(addr1).newChallenge(0, 0, 0), "invalid order status reverted").to.be.reverted;

        await CertCoordinator.connect(addr1).newOrder([[0, "*.test.com"], [0, "test2.com"]], 0, 604800);
        let tx = await CertCoordinator.connect(addr1).newChallenge(0, 0, 0);
        let receipt = await tx.wait();
        let newChallengeLogs = receipt["events"].filter(x => x["event"] === "FundsUpdate");
        expect(tx, "invalid order status reverted").to.be.reverted;
        expect(newChallengeLogs.length, "newChallenge should only generate one event").to.eql(1);
        expect(newChallengeLogs[0]["args"], "newChallenge evnet parameter not as expected").to.eql([addr1.address, ethers.BigNumber.from(8)]);
        
        let record = await CertCoordinator.challengeRcds(1);

        await expect(record, "new challenge result not valid")
            .to.eql([addr1.address, ethers.BigNumber.from(0), [ethers.BigNumber.from(0), ethers.BigNumber.from(0), 0], true]);

        await expect(CertCoordinator.fulfillRandomWordsTest(2, [ethers.BigNumber.from(12345678)]), "invalid request ID should be reverted")
            .to.be.reverted;

        tx = await CertCoordinator.fulfillRandomWordsTest(1, [ethers.BigNumber.from(12345678)]);
        receipt = await tx.wait();
        let fulfillRandomWordsLogs = receipt["events"].filter(x => x["event"] === "ChallengeReady");
        expect(fulfillRandomWordsLogs.length, "fulfillRandomWords should only generate one event").to.eql(1);
        expect(fulfillRandomWordsLogs[0]["args"], "fulfillRandomWords event parameter not as expected").to.eql([ethers.BigNumber.from(1), "6T#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"]); 

    });

    it("Check Challenge Test", async function (){
        const {CertCoordinator, addr1} = await loadFixture(deployContractFixture);

        await expect(CertCoordinator.checkChallenge(0, 0, 0, 0), "unregistered user should be reverted")
            .to.be.reverted;

        await expect(CertCoordinator.connect(addr1).newAccount(["sample@test.com", "sample2@test.com"], true),
            "NewAccount event should be created")
            .to.emit(CertCoordinator, "NewAccountLog").withArgs(addr1.address, "created");

        await expect(CertCoordinator.connect(addr1).checkChallenge(0, 0, 0, 0), "not sufficient funds should be reverted").to.be.reverted;        
        await CertCoordinator.onTokenTransfer(addr1.address, ethers.BigNumber.from("200000000000000000"), 0x0);

        await expect(CertCoordinator.connect(addr1).checkChallenge(0, 0, 0, 3), "inproper challenge type should be reverted").to.be.reverted;
        await expect(CertCoordinator.connect(addr1).checkChallenge(0, 0, 0, 0), "invalid order status reverted").to.be.reverted;

        await CertCoordinator.connect(addr1).newOrder([[0, "*.test.com"], [0, "test2.com"]], 0, 604800);
        await expect(CertCoordinator.connect(addr1).checkChallenge(0, 0, 0, 0), "invalid challenge status reverted").to.be.reverted;

        await CertCoordinator.connect(addr1).newChallenge(0, 0, 0);
        await expect(CertCoordinator.fulfillRandomWordsTest(1, [ethers.BigNumber.from(12345678)]))
            .to.emit(CertCoordinator, "ChallengeReady").withArgs(ethers.BigNumber.from(1), "6T#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");

        await CertCoordinator.connect(addr1).checkChallenge(0, 0, 0, 0);

        await expect(CertCoordinator.fulfillTest(ethers.utils.hexZeroPad(ethers.utils.hexlify(2), 32), "6T#!!!!!!!!!!!!!!!!!!!!!!!!!!!!?"),
            "challenge check with unmatched token should fail")
            .to.emit(CertCoordinator, "ChallStatus").withArgs(addr1.address, 0, 0, 0, false);

        await expect(CertCoordinator.fulfillTest(ethers.utils.hexZeroPad(ethers.utils.hexlify(2), 32), "6T#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"),
            "challenge check with matched token should success")
            .to.emit(CertCoordinator, "ChallStatus").withArgs(addr1.address, 0, 0, 0, true);

        let result = await CertCoordinator.connect(addr1).getUserInfo();
        expect(result["orders"][0]["authorizations"][0]["challenges"][0]["validated"], "successful check will update challenge status")
            .to.equal(true);
    });

    it("Update Authorization Test", async function () {
        const {CertCoordinator, addr1} = await loadFixture(deployContractFixture);

        await expect(CertCoordinator.connect(addr1).updateAuth(0), "unregistered user should be reverted")
            .to.be.reverted;

        await expect(CertCoordinator.connect(addr1).newAccount(["sample@test.com", "sample2@test.com"], true),
            "NewAccount event should be created")
            .to.emit(CertCoordinator, "NewAccountLog").withArgs(addr1.address, "created");

        await expect(CertCoordinator.connect(addr1).updateAuth(0), "invalid order should be reverted")
            .to.be.reverted;

        await CertCoordinator.connect(addr1).newOrder([[0, "*.test.com"], [0, "test2.com"]], 0, 604800);

        await CertCoordinator.onTokenTransfer(addr1.address, ethers.BigNumber.from("400000000000000000"), 0x0);
        // control expired time
        const curBlock = await ethers.provider.getBlock();
        await ethers.provider.send('evm_setNextBlockTimestamp', [curBlock.timestamp + 4800]); 
        await ethers.provider.send('evm_mine');
        
        await expect(CertCoordinator.connect(addr1).updateAuth(0), "order status should not be valid since authorizations not fully executed")
        .to.emit(CertCoordinator, "OrderStatus").withArgs(addr1.address, 0, false);
    
        await CertCoordinator.connect(addr1).newChallenge(0, 0, 0);
        await expect(CertCoordinator.fulfillRandomWordsTest(1, [ethers.BigNumber.from(12345678)]))
            .to.emit(CertCoordinator, "ChallengeReady").withArgs(ethers.BigNumber.from(1), "6T#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");

        await CertCoordinator.connect(addr1).checkChallenge(0, 0, 0, 0);
        await expect(CertCoordinator.fulfillTest(ethers.utils.hexZeroPad(ethers.utils.hexlify(2), 32), "6T#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"),
            "challenge check with matched token should success")
            .to.emit(CertCoordinator, "ChallStatus").withArgs(addr1.address, 0, 0, 0, true);
        
        await expect(CertCoordinator.connect(addr1).updateAuth(0), "order status should not be valid since authorizations not fully executed")
            .to.emit(CertCoordinator, "OrderStatus").withArgs(addr1.address, 0, false);
            
        await CertCoordinator.connect(addr1).newChallenge(0, 1, 0);
        await expect(CertCoordinator.fulfillRandomWordsTest(1, [ethers.BigNumber.from(12345678)]))
            .to.emit(CertCoordinator, "ChallengeReady").withArgs(ethers.BigNumber.from(1), "6T#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");

        await CertCoordinator.connect(addr1).checkChallenge(0, 1, 0, 0);
        await expect(CertCoordinator.fulfillTest(ethers.utils.hexZeroPad(ethers.utils.hexlify(2), 32), "6T#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"),
            "challenge check with matched token should success")
            .to.emit(CertCoordinator, "ChallStatus").withArgs(addr1.address, 0, 1, 0, true);
        
        await expect(CertCoordinator.connect(addr1).updateAuth(0), "order status should be valid since authorizations fully executed")
            .to.emit(CertCoordinator, "OrderStatus").withArgs(addr1.address, 0, true);

    });

    it("Set Certification Test", async function () {
        const {CertCoordinator, addr1} = await loadFixture(deployContractFixture);

        await expect(CertCoordinator.connect(addr1).setCertificate(0, "testhash"), "unregistered account reverted")
            .to.be.reverted;

        await expect(CertCoordinator.connect(addr1).newAccount(["sample@test.com", "sample2@test.com"], true),
            "NewAccount event should be created")
            .to.emit(CertCoordinator, "NewAccountLog").withArgs(addr1.address, "created");
    
        await expect(CertCoordinator.connect(addr1).setCertificate(0, "testhash"), "revert since order not fully authenticated")
            .to.be.reverted;

        await CertCoordinator.onTokenTransfer(addr1.address, ethers.BigNumber.from("400000000000000000"), 0x0);
            
        await CertCoordinator.connect(addr1).newOrder([[0, "*.test.com"], [0, "test2.com"]], 0, 604800);

        // control expired time
        const curBlock = await ethers.provider.getBlock();
        await ethers.provider.send('evm_setNextBlockTimestamp', [curBlock.timestamp + 4800]); 
        await ethers.provider.send('evm_mine');

        await expect(CertCoordinator.connect(addr1).setCertificate(0, "testhash"), "revert since order not fully authenticated")
            .to.be.reverted;

        await CertCoordinator.connect(addr1).newChallenge(0, 0, 0);
        await expect(CertCoordinator.fulfillRandomWordsTest(1, [ethers.BigNumber.from(12345678)]))
            .to.emit(CertCoordinator, "ChallengeReady").withArgs(ethers.BigNumber.from(1), "6T#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        
        await expect(CertCoordinator.connect(addr1).setCertificate(0, "testhash"), "revert since order not fully authenticated")
            .to.be.reverted;

        await CertCoordinator.connect(addr1).checkChallenge(0, 0, 0, 0);
        await expect(CertCoordinator.fulfillTest(ethers.utils.hexZeroPad(ethers.utils.hexlify(2), 32), "6T#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"),
            "challenge check with matched token should success")
            .to.emit(CertCoordinator, "ChallStatus").withArgs(addr1.address, 0, 0, 0, true);

        await expect(CertCoordinator.connect(addr1).setCertificate(0, "testhash"), "revert since order not fully authenticated")
            .to.be.reverted;

        await CertCoordinator.connect(addr1).newChallenge(0, 1, 0);
        await expect(CertCoordinator.fulfillRandomWordsTest(1, [ethers.BigNumber.from(12345678)]))
            .to.emit(CertCoordinator, "ChallengeReady").withArgs(ethers.BigNumber.from(1), "6T#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");

        await expect(CertCoordinator.connect(addr1).setCertificate(0, "testhash"), "revert since order not fully authenticated")
            .to.be.reverted;

        await CertCoordinator.connect(addr1).checkChallenge(0, 1, 0, 0);
        await expect(CertCoordinator.fulfillTest(ethers.utils.hexZeroPad(ethers.utils.hexlify(2), 32), "6T#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"),
            "challenge check with matched token should success")
            .to.emit(CertCoordinator, "ChallStatus").withArgs(addr1.address, 0, 1, 0, true);
        
        await expect(CertCoordinator.connect(addr1).setCertificate(0, "testhash"), "revert since order not fully authenticated")
            .to.be.reverted;

        await expect(CertCoordinator.connect(addr1).updateAuth(0), "order status should be valid since authorizations fully executed")
            .to.emit(CertCoordinator, "OrderStatus").withArgs(addr1.address, 0, true);

        await expect(CertCoordinator.connect(addr1).setCertificate(0, "testhash"), "should be successful since order is authorized")
            .to.emit(CertCoordinator, "NewCert").withArgs(addr1.address, 0, "testhash");
        
        await expect(CertCoordinator.connect(addr1).setCertificate(0, "testhash"), "should be reverted since certificate already set")
            .to.be.reverted;

        const certificateRecord = await CertCoordinator.CertRcds(0);

        expect(certificateRecord, "certificate parameters not properly set")
            .to.eql([ethers.BigNumber.from(curBlock.timestamp+604800),
                ethers.BigNumber.from(0), 
                ethers.BigNumber.from(0), 
                "testhash", 
                1,
                addr1.address,
                ethers.BigNumber.from(0)]);
        
    });

    it("Revoke Certificate Test", async function () {
        const {CertCoordinator, addr1} = await loadFixture(deployContractFixture);

        await expect(CertCoordinator.connect(addr1).revokeCertificate(0), "unregistered account reverted")
            .to.be.reverted;

        await expect(CertCoordinator.connect(addr1).newAccount(["sample@test.com", "sample2@test.com"], true),
            "NewAccount event should be created")
            .to.emit(CertCoordinator, "NewAccountLog").withArgs(addr1.address, "created");
    
        await expect(CertCoordinator.connect(addr1).revokeCertificate(0), "revert since certificate not valid")
            .to.be.reverted;

        await CertCoordinator.onTokenTransfer(addr1.address, ethers.BigNumber.from("400000000000000000"), 0x0);
            
        await CertCoordinator.connect(addr1).newOrder([[0, "*.test.com"], [0, "test2.com"]], 0, 604800);

        // control expired time
        const curBlock = await ethers.provider.getBlock();
        await ethers.provider.send('evm_setNextBlockTimestamp', [curBlock.timestamp + 4800]); 
        await ethers.provider.send('evm_mine');

        await expect(CertCoordinator.connect(addr1).revokeCertificate(0), "revert since certificate not valid")
            .to.be.reverted;

        await CertCoordinator.connect(addr1).newChallenge(0, 0, 0);
        await expect(CertCoordinator.fulfillRandomWordsTest(1, [ethers.BigNumber.from(12345678)]))
            .to.emit(CertCoordinator, "ChallengeReady").withArgs(ethers.BigNumber.from(1), "6T#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        
        await expect(CertCoordinator.connect(addr1).revokeCertificate(0), "revert since certificate not valid")
            .to.be.reverted;

        await CertCoordinator.connect(addr1).checkChallenge(0, 0, 0, 0);
        await expect(CertCoordinator.fulfillTest(ethers.utils.hexZeroPad(ethers.utils.hexlify(2), 32), "6T#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"),
            "challenge check with matched token should success")
            .to.emit(CertCoordinator, "ChallStatus").withArgs(addr1.address, 0, 0, 0, true);

        await expect(CertCoordinator.connect(addr1).revokeCertificate(0), "revert since certificate not valid")
            .to.be.reverted;

        await CertCoordinator.connect(addr1).newChallenge(0, 1, 0);
        await expect(CertCoordinator.fulfillRandomWordsTest(1, [ethers.BigNumber.from(12345678)]))
            .to.emit(CertCoordinator, "ChallengeReady").withArgs(ethers.BigNumber.from(1), "6T#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");

        await expect(CertCoordinator.connect(addr1).revokeCertificate(0), "revert since certificate not valid")
            .to.be.reverted;

        await CertCoordinator.connect(addr1).checkChallenge(0, 1, 0, 0);
        await expect(CertCoordinator.fulfillTest(ethers.utils.hexZeroPad(ethers.utils.hexlify(2), 32), "6T#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"),
            "challenge check with matched token should success")
            .to.emit(CertCoordinator, "ChallStatus").withArgs(addr1.address, 0, 1, 0, true);
        
        await expect(CertCoordinator.connect(addr1).revokeCertificate(0), "revert since certificate not valid")
            .to.be.reverted;

        await expect(CertCoordinator.connect(addr1).updateAuth(0), "order status should be valid since authorizations fully executed")
            .to.emit(CertCoordinator, "OrderStatus").withArgs(addr1.address, 0, true);

        await expect(CertCoordinator.connect(addr1).revokeCertificate(0), "revert should success once the ")
            .to.be.reverted;
    });


});