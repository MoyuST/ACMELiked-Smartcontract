// SPDX-License-Identifier: MIT
pragma solidity >=0.8.17;

import "@openzeppelin/contracts/utils/Strings.sol";
import "@chainlink/contracts/src/v0.8/VRFV2WrapperConsumerBase.sol";
import "@chainlink/contracts/src/v0.8/interfaces/ERC677ReceiverInterface.sol";
import "@chainlink/contracts/src/v0.8/ChainlinkClient.sol";

contract ACMEDataFormat {
    enum Status {
        invalid,
        valid,
        pending, 
        ready, 
        processing
    }

    enum ChallengeType {
        http_01,
        dns_01
    }

    enum IdentifierType {
        dns
    }

    struct Account {
        Status status;
        string[] contact;
        bool termOfServiceAgreed;
        // externalAccountBinding (not supported)
        Order[] orders;
    }

    // ! need to check wildcard
    struct Order {
        Status status;
        uint256 expires;
        Identifier[] identifiers; // content should be immutable
        uint256 notBefore;
        uint256 notAfter;
        Authorization[] authorizations; // content should be immutable
    }

    struct Identifier {
        IdentifierType identifierType;
        string value;
    }

    struct Authorization {
        Status status;
        uint256 expires;
        Identifier identifier;
        Challenge[] challenges;
        bool wildcard;
    }

    struct Challenge {
        ChallengeType challengeType;
        Status status;
        string token;
        bool validated;
    }

    struct Certificate {
        uint256 expires;
        Identifier[] identifiers; // content should be immutable
        uint256 notBefore;
        uint256 notAfter;
        string hash;
    }
}

contract CertCoordinator is ChainlinkClient, ACMEDataFormat, VRFV2WrapperConsumerBase, ERC677ReceiverInterface {
    /*
     * import
     *
     */
    using Chainlink for Chainlink.Request;

    /*
     * struct
     *
     */
    struct ChallengeReq {
        uint256 orderIdx;
        uint256 authIdx;
        ChallengeType challengeType;
    }

    struct CheckReq {
        address requestAddr;
        uint256 orderIdx;
        uint256 authIdx;
        uint256 challIdx;
        string token;
        bool valid;
    }

    struct ChallengeRequestRcd {
        address requestAddr;
        uint256 challIdx;
        ChallengeReq challReq;
        bool valid;
    }

    /*
     * hardcode information
     *
     */
    // Address LINK - hardcoded for Goerli
    address linkAddress = 0x326C977E6efc84E512bB9C30f76E30c160eD06FB;
    // address WRAPPER - hardcoded for Goerli
    address wrapperAddress = 0x708701a1DfF4f478de54383E49a627eD4852C816;
    uint16 public _requestConfirmations = 3; // default
    uint32 public _numWords = 1; // default
    uint32 public _callbackGasLimit = 100000;
    uint256 public _challengeCheckFee = 100000000000000000;
    uint256 public requestCounter = 0;
    
    string public termOfService;
    bool public contractValid;
    address public owner;

    mapping(address => Account) public accounts;
    mapping(uint256 => ChallengeRequestRcd) public challengeRcds;
    mapping(address => uint256) public funds;
    mapping (bytes32 => CheckReq) public checkRcds;
    mapping (uint256 => Certificate) public CertRcds;

    /*
     * error
     * provide more information to users when operations failed
     *
     */
    error VisitInvalidLog();
    error NotEnoughTokenFee(uint256 estimatedMinimumFee);
    // error NewOrderInvaidOrderRange();
    // error NewOrderRangeLargerThan7Days();
    // error NewOderNumberOfOrdersExceed100000();
    // error NewOrderIdenNotSupported();
    error UnsupportChallType();
    error IllegalAccountRequest();
    error invalidVRFRequestID();
    // error OrderNotProcessing();
    // error AuthNotProcessing();

    /*
     * event
     * provide some necessary information
     *
     */
    event NewAccountLog(address indexed _userAddress, string indexed _additinalInfo);
    event NewOrderLog(address indexed _userAddress, uint256 indexed _curOrderIdx, uint256 _curIdenIdx);
    event NewChallengeLog(address indexed _userAddress, string indexed _status, string _additinalInfo);
    event invalidVRFRequestIDLog(uint256 indexed  _requestID);
    event ChallengeReady(uint256 indexed _requestID, string indexed _token);
    event FundsUpdate(address indexed _sender, uint256 indexed _amount);
    event ChallStatus(address indexed _sender, uint256 indexed _orderIdx, uint256 indexed _authIdx, uint256  _challIdx, bool success);
    event OrderStatus(address indexed _sender, uint256 indexed _orderIdx, bool success);
    event NewCert(address indexed _sender, uint256 indexed _orderIdx, string _hash);

    /*
     * modifier
     *
     */
    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    modifier onlyContractValid {
        if(!contractValid){
            revert VisitInvalidLog();
        }
        require(contractValid == true);
        _;
    }

    modifier onlyRegisteredAccount {
        if(accounts[msg.sender].status == Status.valid){
            revert IllegalAccountRequest();
        }
        require(accounts[msg.sender].status == Status.valid);
        _;
    }

    /*
     * constructor
     *
     */
    constructor() VRFV2WrapperConsumerBase(linkAddress, wrapperAddress) {
        owner = msg.sender;
        contractValid = true;
        setChainlinkToken(linkAddress);
        setChainlinkOracle(0xCC79157eb46F5624204f47AB42b3906cAA40eaB7);
    }

    /*
     * function
     *
     */

    function deactivateContract() external onlyOwner onlyContractValid {
        contractValid = false;
    }

    // register/update/delete account's infomation
    function newAccount(string[] memory contact, bool termOfServiceAgreed) external onlyContractValid {
        Account storage ref = accounts[msg.sender];
        if(termOfServiceAgreed == true){
            // Status preStatus = ref.status;
            ref.status = Status.valid;
            ref.contact = contact;
            ref.termOfServiceAgreed = true;

            // if(preStatus==Status.valid){
            //     emit NewAccountLog(msg.sender, "created");
            // }
            // else{
            emit NewAccountLog(msg.sender, "U");
            // }
        }
        else{
            // this means that once a user deactivate its account,
            // he cannot restore all his information, this is used for security
            ref.status = Status.invalid;
            delete accounts[msg.sender];
            emit NewAccountLog(msg.sender, "D");
        }
    }

    // retrieve user's account information
    function getUserInfo() external onlyContractValid view returns (Account memory) {
        return accounts[msg.sender];
    }

    // create order based on user's request. 
    // the order will contains:
    //                  - identifiers
    //                  - authorizations (with challenge empty, users need to call new challenge to create element)
    function newOrder(
        Identifier[] memory identifiers,  
        uint256 notBefore, 
        uint256 notAfter
    ) external onlyContractValid onlyRegisteredAccount{
        
        if(notBefore>notAfter || notAfter-notBefore>604800 || identifiers.length > 100000){
            revert();
        }

        // can only handle identifier with type dns
        for(uint i=0; i<identifiers.length; ++i){
            if(identifiers[i].identifierType!=IdentifierType.dns){
                revert();
            }
        }

        // if(notBefore>notAfter){
        //     revert NewOrderInvaidOrderRange();
        // }
        // if(notAfter-notBefore>604800){
        //     revert NewOrderRangeLargerThan7Days();
        // }
        // if(identifiers.length > 100000){
        //     revert NewOderNumberOfOrdersExceed100000();
        // }

        Account storage curAccount = accounts[msg.sender];
        curAccount.orders.push();
        uint curOrderIdx = curAccount.orders.length - 1;
        Order storage curOrder = curAccount.orders[curOrderIdx];
        curOrder.status = Status.processing;
        curOrder.expires = block.timestamp + 604800;
        curOrder.notBefore = notBefore;
        curOrder.notAfter = notAfter;

        for(uint i=0; i<identifiers.length; ++i){
            curOrder.identifiers.push();
            curOrder.authorizations.push();

            uint256 curIdenIdx = curOrder.identifiers.length - 1;

            curOrder.identifiers[curIdenIdx].identifierType = IdentifierType.dns;

            bytes memory strBytes = bytes(identifiers[i].value);
            uint256 trimStartIdx = 0; // used to remove *. at the beginning of value
            uint256 endIndex = strBytes.length;
            bool wildCard = false;

            if(strBytes.length > 2 && strBytes[0]=='*' && strBytes[1]=='.'){
                wildCard = true;
                trimStartIdx+=2;
            }
            
            bytes memory result = new bytes(endIndex-trimStartIdx);

            for(uint j = trimStartIdx; j < endIndex; ++j) {
                result[i-trimStartIdx] = strBytes[j];
            }
            
            curOrder.identifiers[curIdenIdx].value = string(result);

            Authorization storage curAuth = curOrder.authorizations[curIdenIdx];

            curAuth.identifier.value = string(result);
            curAuth.status = Status.processing;
            curAuth.expires = block.timestamp + 604800;
            curAuth.identifier.value = string(result);
            curAuth.identifier.identifierType = IdentifierType.dns;
            curAuth.wildcard = wildCard;

            emit NewOrderLog(msg.sender, curIdenIdx, curOrderIdx);
        }
    }

    // user top off funds
    function onTokenTransfer(
        address _sender,
        uint256 _amount,
        bytes calldata // _data
    ) external override {
        funds[_sender] += _amount;
        emit FundsUpdate(_sender, funds[_sender]);
    }

    // user withdraw funds
    function tokenWithdraw(uint256 _amount) external {
        if(funds[msg.sender]>=_amount){
            funds[msg.sender]-=_amount;
            // LinkTokenInterface LINK = LinkTokenInterface(linkAddress);
            // LINK.transfer(msg.sender, _amount);
            LinkTokenInterface(linkAddress).transfer(msg.sender, _amount);
        }
    }

    function newChallenge(
        uint256 orderIdx,
        uint256 authIdx,
        ChallengeType challengeType
    ) external {
        uint256 estimatedValue = VRF_V2_WRAPPER.calculateRequestPrice(_callbackGasLimit);
        if(funds[msg.sender] < estimatedValue) {
            revert NotEnoughTokenFee(estimatedValue);
        }

        if(challengeType!=ChallengeType.http_01 && challengeType!=ChallengeType.dns_01){
            revert UnsupportChallType();
        }

        Order storage curOrder = accounts[msg.sender].orders[orderIdx];
        Authorization storage curAuth = curOrder.authorizations[authIdx];

        if(curOrder.status!=Status.processing || curAuth.status!=Status.processing){
            revert();
        }

        // if(curAuth.status!=Status.processing){
        //     revert AuthNotProcessing();
        // }

        // deduct funds first to avoid reentrant attack
        funds[msg.sender] -= estimatedValue;
        emit FundsUpdate(msg.sender, funds[msg.sender]);
        uint256 requestId = requestRandomness(_callbackGasLimit, _requestConfirmations, _numWords);
        curAuth.challenges.push();
        uint256 challIdx = curAuth.challenges.length;
        Challenge storage curChall = curAuth.challenges[challIdx];
        curChall.challengeType = challengeType;
        curChall.status = Status.pending;
        
        challengeRcds[requestId].challIdx=challIdx;
        challengeRcds[requestId].challReq.orderIdx=orderIdx;
        challengeRcds[requestId].challReq.authIdx=authIdx;
        challengeRcds[requestId].challReq.challengeType=challengeType;
        challengeRcds[requestId].requestAddr=msg.sender;
        challengeRcds[requestId].valid=true;
    }

    function checkChallenge(
        uint256 orderIdx,
        uint256 authIdx,
        uint256 challIdx,
        ChallengeType challengeType
    ) external {
        Order storage curOrder = accounts[msg.sender].orders[orderIdx];
        Authorization storage curAuth = curOrder.authorizations[authIdx];

        if(funds[msg.sender]<_challengeCheckFee){
            revert NotEnoughTokenFee(_challengeCheckFee);
        }

        if(challengeType!=ChallengeType.http_01 || curOrder.status!=Status.processing || curAuth.status!=Status.processing){
            revert();
        }

        // if(curOrder.status!=Status.processing){
        //     revert OrderNotProcessing();
        // }


        // if(curAuth.status!=Status.processing){
        //     revert AuthNotProcessing();
        // }

        // deduct funds first to avoid reentrant attack
        funds[msg.sender] -= _challengeCheckFee;

        string memory urlProtocal = "http://";
        string memory urlPre = curAuth.identifier.value;
        string memory urlMid = "/acme-challenge/";
        string memory urlSuf = curAuth.challenges[challIdx].token;

        Chainlink.Request memory req = buildChainlinkRequest("7d80a6386ef543a3abb52817f6707e3b", address(this), this.fulfill.selector);
        req.add(
            "get",
            string.concat(urlProtocal, urlPre, urlMid, urlSuf)
        );
        req.add("path", "token");
        sendChainlinkRequest(req, (1 * LINK_DIVISIBILITY) / 10); // 0,1*10**18 LINK

        CheckReq storage curRcd = checkRcds[req.id];
        curRcd.orderIdx = orderIdx;
        curRcd.authIdx = authIdx;
        curRcd.challIdx = challIdx;
        curRcd.token = urlSuf;
        curRcd.valid = true;
        curRcd.requestAddr = msg.sender;

    }

    // update users challenge
    function fulfillRandomWords(uint256 _requestId, uint256[] memory _randomWords) internal override {
        if(challengeRcds[_requestId].valid==false){
            emit invalidVRFRequestIDLog(_requestId);
            revert invalidVRFRequestID();
        }

        uint256 rt = _randomWords[0];

        bytes memory bytesArray = new bytes(32);

        // make sure every char is readable
        for(uint i=0; i<32;++i){
            bytesArray[i] = bytes1(uint8(33 + (rt>>(8*i))%(126-33))); 
        }

        ChallengeRequestRcd storage curChallRcd = challengeRcds[_requestId];

        address requestAddr = curChallRcd.requestAddr;
        uint256 orderIdx = curChallRcd.challReq.orderIdx;
        uint256 authIdx = curChallRcd.challReq.authIdx;
        uint256 challIdx = curChallRcd.challIdx;
        string memory token = string(bytesArray);

        Challenge storage curChall = accounts[requestAddr].orders[orderIdx].authorizations[authIdx].challenges[challIdx];

        curChall.token = token;
        curChall.status = Status.ready;
        emit ChallengeReady(_requestId, token);
    }

    function fulfill(bytes32 _requestId, string memory _token) public recordChainlinkFulfillment(_requestId) {
        if(checkRcds[_requestId].valid==true){
            string memory token = checkRcds[_requestId].token;
            bool checkResult=false;
            address userAddr = checkRcds[_requestId].requestAddr;
            uint256 orderIdx = checkRcds[_requestId].orderIdx;
            uint256 authIdx = checkRcds[_requestId].authIdx;
            uint256 challIdx = checkRcds[_requestId].challIdx;
            Authorization storage curAuth = accounts[userAddr].orders[orderIdx].authorizations[authIdx];
            
            if(keccak256(bytes(token)) == keccak256(bytes(_token))){
                curAuth.challenges[challIdx].validated=true;
                curAuth.status = Status.valid;
                checkResult = true;
            }

            emit ChallStatus(userAddr, orderIdx, authIdx, challIdx, checkResult);
        }
    }

    function updateAuth(uint256 orderIdx) external {
        Order storage curOrder = accounts[msg.sender].orders[orderIdx];

        if(curOrder.status!=Status.processing || curOrder.expires > block.timestamp){
            revert();
        }

        bool allAuthPass = true;
        for(uint i=0;i<curOrder.authorizations.length;++i){
            if(curOrder.authorizations[i].status!=Status.valid){
                allAuthPass = false;
                break;
            }
        }
        
        if(allAuthPass){
            curOrder.status = Status.valid;
        }

        emit OrderStatus(msg.sender, orderIdx, allAuthPass);
    }

    function setCertificate(uint256 orderIdx, string calldata hash) external {
        Order storage curOrder = accounts[msg.sender].orders[orderIdx];
        if(curOrder.status!=Status.valid){
            revert ();
        }

        Certificate storage curCert = CertRcds[requestCounter];
        curCert.expires = curOrder.expires;
        curCert.identifiers = curOrder.identifiers;
        curCert.notBefore = curOrder.notBefore;
        curCert.notAfter = curCert.notAfter;
        curCert.hash = hash;

        emit NewCert(msg.sender, orderIdx, hash);
    }

}