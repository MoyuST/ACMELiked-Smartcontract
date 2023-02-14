// SPDX-License-Identifier: MIT
pragma solidity >=0.8.7;

import "@openzeppelin/contracts/utils/Strings.sol";
import "@chainlink/contracts/src/v0.8/VRFV2WrapperConsumerBase.sol";
import "@chainlink/contracts/src/v0.8/interfaces/ERC677ReceiverInterface.sol";

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
        ChallengeType challenType;
    }

}

contract CertCoordinator is ACMEDataFormat, VRFV2WrapperConsumerBase, ERC677ReceiverInterface {

    // "newNonce": "https://example.com/acme/new-nonce", // not needed, since blockchain has already avoid double spend problem
    //  "newAccount": "https://example.com/acme/new-account",
    //  "newOrder": "https://example.com/acme/new-order",
    //  "newAuthz": "https://example.com/acme/new-authz", // needed or not depend on whether pre-authorization
    //  "revokeCert": "https://example.com/acme/revoke-cert",
    //  "keyChange": "https://example.com/acme/key-change", // not allowed, private key of the account is only source of secret
    //  "meta": {
    //    "termsOfService": "https://example.com/acme/terms/2017-5-30",
    //    "website": "https://www.example.com/",
    //    "caaIdentities": ["example.com"],
    //    "externalAccountRequired": false
    //  }

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

    string public termOfService;
    bool public contractValid;
    address public owner;
    uint16 public _requestConfirmations = 3; // default
    uint32 public _numWords = 1; // default
    uint32 public _callbackGasLimit = 100000;

    mapping(address => Account) public accounts;
    mapping(uint256 => ChallengeRequestRcds) public challengeRcds;

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
    error IllegalAccountRequest();
    error invalidVRFRequestID();

    event NewAccountLog(address indexed _userAddress, string indexed _additinalInfo);
    event NewOrderLog(address indexed _userAddress, uint256 indexed _curOrderIdx, uint256 _curIdenIdx);
    event NewChallengeLog(address indexed _userAddress, string indexed _status, string _additinalInfo);
    event invalidVRFRequestIDLog(uint256 indexed  _requestID);
    event ChallengeReady(uint256 _requestID, string indexed _token);

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
    }

    function deactivateContract() external onlyOwner onlyContractValid {
        contractValid = false;
    }

    // register/update/delete account's infomation
    function newAccount(string[] memory contact, bool termOfServiceAgreed) external onlyContractValid {
        if(termOfServiceAgreed == true){
            Status preStatus = accounts[msg.sender].status;
            accounts[msg.sender].status = Status.valid;
            accounts[msg.sender].contact = contact;
            accounts[msg.sender].termOfServiceAgreed = true;

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
            accounts[msg.sender].status = Status.invalid;
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

    // accepting users' requests and responds
    function onTokenTransfer(
        address sender,
        uint256 _amount,
        bytes calldata _data
    ) external override {
        uint256 estimatedValue = VRF_V2_WRAPPER.calculateRequestPrice(_callbackGasLimit);
        if (_amount < estimatedValue) {
            revert NotEnoughTokenFee(estimatedValue);
        }

        ChallengeReq memory chaReq = abi.decode(_data, (ChallengeReq));

        if(accounts[sender].orders[chaReq.orderIdx].status!=Status.processing){
            revert NewChallWithOrderNotProcessing();
        }

        if(accounts[sender].orders[chaReq.orderIdx].authorizations[chaReq.authIdx].status!=Status.processing){
            revert NewChallWithAuthNotProcessing();
        }

        uint256 requestId = requestRandomness(_callbackGasLimit, _requestConfirmations, _numWords);
        accounts[sender].orders[chaReq.orderIdx].authorizations[chaReq.authIdx].challenges.push();
        uint256 challIdx = accounts[sender].orders[chaReq.orderIdx].authorizations[chaReq.authIdx].challenges.length;
        accounts[sender].orders[chaReq.orderIdx].authorizations[chaReq.authIdx].challenges[challIdx].challengeType
            = chaReq.challenType;
        accounts[sender].orders[chaReq.orderIdx].authorizations[chaReq.authIdx].challenges[challIdx].status
            = Status.pending;
        
        challengeRcds[requestId].challIdx=challIdx;
        challengeRcds[requestId].challReq=chaReq;
        challengeRcds[requestId].requestAddr=sender;
        challengeRcds[requestId].valid=true;

    }

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



}