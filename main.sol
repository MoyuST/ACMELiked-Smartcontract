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
        uint256 validated;
    }

    struct ChallengeReq {
        uint256 orderIdx;
        uint256 authIdx;
        ChallengeType challengeType;
    }
}

contract ACMEError {
    
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
    struct ChallengeRequestRcds {
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
    
    string public termOfService;
    bool public contractValid;
    address public owner;

    mapping(address => Account) public accounts;
    mapping(uint256 => ChallengeRequestRcds) public challengeRcds;
    mapping(address => uint256) public funds;

    /*
     * Error
     * Provide more information to users when operations failed
     */
    error VisitInvalidLog();
    error NotEnoughTokenFee(uint256 estimatedMinimumFee);
    error NewOrderInvaidOrderRange();
    error NewOrderRangeLargerThan7Days();
    error NewOderNumberOfOrdersExceed100000();
    error NewOrderIdenNotSupported();
    error NewChallWithOrderNotProcessing();
    error NewChallWithAuthNotProcessing();
    error NewChallWithUnsupportType();
    error IllegalAccountRequest();
    error invalidVRFRequestID();
    error CheckChallWithOrderNotProcessing();
    error CheckChallWithAuthNotProcessing();
    error CheckChallNoEnoughFunds();

    event NewAccountLog(address indexed _userAddress, string indexed _additinalInfo);
    event NewOrderLog(address indexed _userAddress, uint256 indexed _curOrderIdx, uint256 _curIdenIdx);
    event NewChallengeLog(address indexed _userAddress, string indexed _status, string _additinalInfo);
    event invalidVRFRequestIDLog(uint256 indexed  _requestID);
    event ChallengeReady(uint256 _requestID, string indexed _token);
    event FundsUpdate(address _sender, uint256 _amount);

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

    constructor() VRFV2WrapperConsumerBase(linkAddress, wrapperAddress) {
        owner = msg.sender;
        contractValid = true;
        setChainlinkToken(linkAddress);
        setChainlinkOracle(0xCC79157eb46F5624204f47AB42b3906cAA40eaB7);
    }

    function deactivateContract() external onlyOwner onlyContractValid {
        contractValid = false;
    }

    // register/update/delete account's infomation
    function newAccount(string[] memory contact, bool termOfServiceAgreed) external onlyContractValid {
        Account storage ref = accounts[msg.sender];
        if(termOfServiceAgreed == true){
            Status preStatus = ref.status;
            ref.status = Status.valid;
            ref.contact = contact;
            ref.termOfServiceAgreed = true;

            if(preStatus==Status.valid){
                emit NewAccountLog(msg.sender, "created");
            }
            else{
                emit NewAccountLog(msg.sender, "updated");
            }
        }
        else{
            // this means that once a user deactivate its account,
            // he cannot restore all his information, this is used for security
            ref.status = Status.invalid;
            delete accounts[msg.sender];
            emit NewAccountLog(msg.sender, "deleted");
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

        if(notBefore>notAfter){
            revert NewOrderInvaidOrderRange();
        }
        if(notAfter-notBefore>604800){
            revert NewOrderRangeLargerThan7Days();
        }
        if(identifiers.length > 100000){
            revert NewOderNumberOfOrdersExceed100000();
        }

        accounts[msg.sender].orders.push();
        uint curOrderIdx = accounts[msg.sender].orders.length - 1;
        accounts[msg.sender].orders[curOrderIdx].status = Status.processing;
        accounts[msg.sender].orders[curOrderIdx].expires = block.timestamp + 604800;
        accounts[msg.sender].orders[curOrderIdx].notBefore = notBefore;
        accounts[msg.sender].orders[curOrderIdx].notAfter = notAfter;

        // Identifier[] identifiers; // content should be immutable
        // Authorization[] authorizations; // content should be immutable

        for(uint i=0; i<identifiers.length; ++i){
            // can only handle identifier with type dns
            if(identifiers[i].identifierType==IdentifierType.dns){
                accounts[msg.sender].orders[curOrderIdx].identifiers.push();
                accounts[msg.sender].orders[curOrderIdx].authorizations.push();

                uint256 curIdenIdx = accounts[msg.sender].orders[curOrderIdx].identifiers.length - 1;

                accounts[msg.sender].orders[curOrderIdx].identifiers[curIdenIdx].identifierType = IdentifierType.dns;

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
                
                accounts[msg.sender].orders[curOrderIdx].identifiers[curIdenIdx].value = string(result);
                accounts[msg.sender].orders[curOrderIdx].authorizations[curIdenIdx].identifier.value = string(result);
                accounts[msg.sender].orders[curOrderIdx].authorizations[curIdenIdx].status = Status.processing;
                accounts[msg.sender].orders[curOrderIdx].authorizations[curIdenIdx].expires = block.timestamp + 604800;
                accounts[msg.sender].orders[curOrderIdx].authorizations[curIdenIdx].identifier.value = string(result);
                accounts[msg.sender].orders[curOrderIdx].authorizations[curIdenIdx].identifier.identifierType = IdentifierType.dns;
                accounts[msg.sender].orders[curOrderIdx].authorizations[curIdenIdx].wildcard = wildCard;

                emit NewOrderLog(msg.sender, curIdenIdx, curOrderIdx);
            }
            else{
                revert NewOrderIdenNotSupported();
            }
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
            LinkTokenInterface LINK = LinkTokenInterface(linkAddress);
            LINK.transfer(msg.sender, _amount);
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
            revert NewChallWithUnsupportType();
        }

        if(accounts[msg.sender].orders[orderIdx].status!=Status.processing){
            revert NewChallWithOrderNotProcessing();
        }

        if(accounts[msg.sender].orders[orderIdx].authorizations[authIdx].status!=Status.processing){
            revert NewChallWithAuthNotProcessing();
        }

        uint256 requestId = requestRandomness(_callbackGasLimit, _requestConfirmations, _numWords);
        accounts[msg.sender].orders[orderIdx].authorizations[authIdx].challenges.push();
        uint256 challIdx = accounts[msg.sender].orders[orderIdx].authorizations[authIdx].challenges.length;
        accounts[msg.sender].orders[orderIdx].authorizations[authIdx].challenges[challIdx].challengeType
            = challengeType;
        accounts[msg.sender].orders[orderIdx].authorizations[authIdx].challenges[challIdx].status
            = Status.pending;
        
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
        if(funds[msg.sender]<_challengeCheckFee){
            revert CheckChallNoEnoughFunds();
        }

        if(accounts[msg.sender].orders[orderIdx].status!=Status.processing){
            revert CheckChallWithOrderNotProcessing();
        }

        if(accounts[msg.sender].orders[orderIdx].authorizations[authIdx].status!=Status.processing){
            revert CheckChallWithAuthNotProcessing();
        }

        string memory urlPre = accounts[msg.sender].orders[orderIdx].authorizations[authIdx].identifier.value;
        string memory urlMid = "/acme-challenge/";
        string memory urlSuf = accounts[msg.sender].orders[orderIdx].authorizations[authIdx].challenges[challIdx].token;

        Chainlink.Request memory req = buildChainlinkRequest("7d80a6386ef543a3abb52817f6707e3b", address(this), this.fulfill.selector);
        req.add(
            "get",
            string.concat(urlPre, urlMid, urlSuf)
        );
        req.add("path", "token");
        sendChainlinkRequest(req, (1 * LINK_DIVISIBILITY) / 10); // 0,1*10**18 LINK
    }

    // function request() public {
    //     Chainlink.Request memory req = buildChainlinkRequest("7d80a6386ef543a3abb52817f6707e3b", address(this), this.fulfill.selector);
    //     req.add(
    //         "get",
    //         "http://moyust.cc/acme-challenge/tttttttttttt"
    //     );
    //     req.add("path", "token");
    //     sendChainlinkRequest(req, (1 * LINK_DIVISIBILITY) / 10); // 0,1*10**18 LINK
    //     cnt = 45;
    // }

    // update users challenge
    function fulfillRandomWords(uint256 _requestId, uint256[] memory _randomWords) internal override {
        if(challengeRcds[_requestId].valid==false){
            emit invalidVRFRequestIDLog(_requestId);
            revert invalidVRFRequestID();
        }

        uint256 rt = _randomWords[0];

        bytes memory bytesArray = new bytes(32);

        for(uint i=0; i<32;++i){
            bytesArray[i] = bytes1(uint8(33 + (rt>>(8*i))%(126-33))); // make sure every char is readable
        }

        address requestAddr = challengeRcds[_requestId].requestAddr;
        uint256 orderIdx = challengeRcds[_requestId].challReq.orderIdx;
        uint256 authIdx = challengeRcds[_requestId].challReq.authIdx;
        uint256 challIdx = challengeRcds[_requestId].challIdx;
        string memory token = string(bytesArray);

        accounts[requestAddr].orders[orderIdx].authorizations[authIdx].challenges[challIdx].token = token;
        accounts[requestAddr].orders[orderIdx].authorizations[authIdx].challenges[challIdx].status = Status.ready;
        emit ChallengeReady(_requestId, token);
    }

    function fulfill(bytes32 _requestId, string memory _id) public recordChainlinkFulfillment(_requestId) {
    
    }

}