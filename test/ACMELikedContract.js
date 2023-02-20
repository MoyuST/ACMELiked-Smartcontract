const { loadFixture } = require("@nomicfoundation/hardhat-network-helpers")
const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("ACME-Likede Contract", function () {
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
});