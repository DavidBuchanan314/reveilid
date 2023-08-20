@0x8ffce8033734ab02;

# IDs And Hashes
##############################

struct Key256 @0xdde44e3286f6a90d {
    u0                      @0  :UInt64;
    u1                      @1  :UInt64;
    u2                      @2  :UInt64;
    u3                      @3  :UInt64;
}

struct Signature512 @0x806749043a129c12 {
    u0                      @0  :UInt64;
    u1                      @1  :UInt64;
    u2                      @2  :UInt64;
    u3                      @3  :UInt64;
    u4                      @4  :UInt64;
    u5                      @5  :UInt64;
    u6                      @6  :UInt64;
    u7                      @7  :UInt64;
}

struct Nonce24 @0xb6260db25d8d7dfc {
    u0                      @0  :UInt64;
    u1                      @1  :UInt64;
    u2                      @2  :UInt64;
}

using PublicKey = Key256;                               # Node id / Hash / DHT key / Route id, etc
using Nonce = Nonce24;                                  # One-time encryption nonce
using Signature = Signature512;                         # Signature block
using TunnelID = UInt64;                                # Id for tunnels
using CryptoKind = UInt32;                              # FOURCC code for cryptography type
using ValueSeqNum = UInt32;                             # sequence numbers for values
using Subkey = UInt32;                                  # subkey index for dht
using Capability = UInt32;                              # FOURCC code for capability

struct TypedKey @0xe2d567a9f1e61b29 {
    kind                    @0  :CryptoKind;
    key                     @1  :PublicKey;
}

struct TypedSignature @0x963170c7298e3884 {
    kind                    @0  :CryptoKind;
    signature               @1  :Signature;
}

# Node Dial Info
################################################################

struct AddressIPV4 @0xdb8769881266a6a0 {
    addr                    @0  :UInt32;                # Address in big endian format
}

struct AddressIPV6 @0xb35d6e6011dc5c20 {
    addr0                   @0  :UInt32;                # \ 
    addr1                   @1  :UInt32;                #  \ Address in big 
    addr2                   @2  :UInt32;                #  / endian format
    addr3                   @3  :UInt32;                # / 
}

struct Address @0x812706e9e57d108b {
    union {
        ipv4                @0  :AddressIPV4;
        ipv6                @1  :AddressIPV6;
    }
}

struct SocketAddress @0x82df4272f4dd3a62 {
    address                 @0  :Address;
    port                    @1  :UInt16;
}

enum ProtocolKind @0xde0bf5787c067d5a {
    udp                     @0;
    ws                      @1;
    wss                     @2;
    tcp                     @3;
}

struct DialInfoUDP @0xbb38a8b8b7024a7c {
    socketAddress           @0  :SocketAddress;
}

struct DialInfoTCP @0x9e0a9371b9a9f7fc {
    socketAddress           @0  :SocketAddress;
}

struct DialInfoWS @0xd7795f7a92ab15b0 {
    socketAddress           @0  :SocketAddress;
    request                 @1  :Text;
}

struct DialInfoWSS @0xe639faa41b7d7b04 {
    socketAddress           @0  :SocketAddress;
    request                 @1  :Text;
}

struct DialInfo @0xe1cd1c39fc2defdf {
    union {
        udp                 @0  :DialInfoUDP;
        tcp                 @1  :DialInfoTCP;
        ws                  @2  :DialInfoWS;
        wss                 @3  :DialInfoWSS;
    }
}

# Signals
##############################

struct SignalInfoHolePunch @0xeeb9ab6861890c9a {
    receipt                 @0  :Data;                  # receipt to return with hole punch
    peerInfo                @1  :PeerInfo;              # peer info of the signal sender for hole punch attempt
}

struct SignalInfoReverseConnect @0xd9ebd3bd0d46e013 {
    receipt                 @0  :Data;                  # receipt to return with reverse connect
    peerInfo                @1  :PeerInfo;              # peer info of the signal sender for reverse connect attempt
}

# Private Routes
##############################

struct RouteHopData @0x8ce231f9d1b7adf2 {         
    nonce                   @0  :Nonce;                 # nonce for encrypted blob
    blob                    @1  :Data;                  # encrypted blob with ENC(nonce,DH(PK,SK))
                                                        # if this is a safety route RouteHopData, there is a single byte tag appended to the end of the encrypted blob
                                                        # it can be one of: 
                                                        #     if more hops remain in this route: RouteHop (0 byte appended as tag)
                                                        #     if end of safety route and starting private route: PrivateRoute (1 byte appended as tag)
                                                        # if this is a private route RouteHopData, only can decode to RouteHop, no tag is appended
}

struct RouteHop @0xf8f672d75cce0c3b {
    node :union {                                       
        nodeId              @0  :PublicKey;             # node id key only for established routes (kind is the same as the pr or sr it is part of)
        peerInfo            @1  :PeerInfo;              # full peer info for this hop to establish the route
    }
    nextHop                 @2  :RouteHopData;          # optional: If this the end of a private route, this field will not exist
                                                        # if this is a safety route routehop, this field is not optional and must exist
}

struct PrivateRoute @0x8a83fccb0851e776 {
    publicKey               @0  :TypedKey;              # private route public key (unique per private route)
    hopCount                @1  :UInt8;                 # Count of hops left in the private route (for timeout calculation purposes only)
    hops :union {
        firstHop            @2  :RouteHop;              # first hop of a private route is unencrypted (hopcount > 0)
        data                @3  :RouteHopData;          # private route has more hops (hopcount > 0 && hopcount < total_hopcount)
        empty               @4  :Void;                  # private route has ended (hopcount = 0)
    }   
} 

struct SafetyRoute @0xf554734d07cb5d59 {
    publicKey               @0  :TypedKey;              # safety route public key (unique per safety route)
    hopCount                @1  :UInt8;                 # Count of hops left in the safety route (for timeout calculation purposes only)
    hops :union {
        data                @2  :RouteHopData;          # safety route has more hops
        private             @3  :PrivateRoute;          # safety route has ended and private route follows
    }
}

# Operations
##############################

enum NetworkClass @0x8cebfc2a6230717f {
    invalid                 @0;                         # X = Invalid network class, network is not yet set up
    inboundCapable          @1;                         # I = Inbound capable without relay, may require signal
    outboundOnly            @2;                         # O = Outbound only, inbound relay required except with reverse connect signal
    webApp                  @3;                         # W = PWA, outbound relay is required in most cases
}

enum DialInfoClass @0x880005edfdd38b1e {
    direct                  @0;                         # D = Directly reachable with public IP and no firewall, with statically configured port
    mapped                  @1;                         # M = Directly reachable with via portmap behind any NAT or firewalled with dynamically negotiated port
    fullConeNAT             @2;                         # F = Directly reachable device without portmap behind full-cone NAT
    blocked                 @3;                         # B = Inbound blocked at firewall but may hole punch with public address
    addressRestrictedNAT    @4;                         # A = Device without portmap behind address-only restricted NAT
    portRestrictedNAT       @5;                         # P = Device without portmap behind address-and-port restricted NAT
}

enum Sequencing @0xb6735890f7818a1c {
    noPreference            @0;
    preferOrdered           @1;
    ensureOrdered           @2;
}

struct DialInfoDetail @0x96423aa1d67b74d8 {
    dialInfo                @0  :DialInfo;
    dialClass               @1  :DialInfoClass;
}

struct NodeStatus @0xd36b9e7a3bf3330d {
    # Reserved for non-nodeinfo status
}

struct ProtocolTypeSet @0x82f12f55a1b73326 {
    udp                     @0  :Bool;
    tcp                     @1  :Bool;
    ws                      @2  :Bool;
    wss                     @3  :Bool;
}

struct AddressTypeSet @0x9f52d5430d349e6b {
    ipv4                    @0  :Bool;
    ipv6                    @1  :Bool;
}

struct SenderInfo @0x8a4464fab4b1d101 {
    socketAddress           @0  :SocketAddress;         # socket address that for the sending peer
}

struct NodeInfo @0xe125d847e3f9f419 {
    networkClass            @0  :NetworkClass;          # network class of this node
    outboundProtocols       @1  :ProtocolTypeSet;       # protocols that can go outbound
    addressTypes            @2  :AddressTypeSet;        # address types supported
    envelopeSupport         @3  :List(UInt8);           # supported rpc envelope/receipt versions
    cryptoSupport           @4  :List(CryptoKind);      # cryptography systems supported
    capabilities            @5  :List(Capability);      # capabilities supported by the node
    dialInfoDetailList      @6  :List(DialInfoDetail);  # inbound dial info details for this node
}

struct SignedDirectNodeInfo @0xe0e7ea3e893a3dd7 {
    nodeInfo                @0  :NodeInfo;              # node info
    timestamp               @1  :UInt64;                # when signed node info was generated
    signatures              @2  :List(TypedSignature);  # signatures
}

struct SignedRelayedNodeInfo @0xb39e8428ccd87cbb {
    nodeInfo                @0  :NodeInfo;              # node info
    relayIds                @1  :List(TypedKey);        # node ids for relay
    relayInfo               @2  :SignedDirectNodeInfo;  # signed node info for relay
    timestamp               @3  :UInt64;                # when signed node info was generated
    signatures              @4  :List(TypedSignature);  # signatures
}

struct SignedNodeInfo @0xd2478ce5f593406a {
    union {
        direct              @0  :SignedDirectNodeInfo;  # node info for nodes reachable without a relay
        relayed             @1  :SignedRelayedNodeInfo; # node info for nodes requiring a relay
    }
}

struct PeerInfo @0xfe2d722d5d3c4bcb {
    nodeIds                 @0  :List(TypedKey);        # node ids for 'closer peer'
    signedNodeInfo          @1  :SignedNodeInfo;        # signed node info for 'closer peer'
}

struct RoutedOperation @0xcbcb8535b839e9dd {
    sequencing              @0  :Sequencing;            # sequencing preference to use to pass the message along
    signatures              @1  :List(Signature);       # signatures from nodes that have handled the private route
    nonce                   @2  :Nonce;                 # nonce Xmsg
    data                    @3  :Data;                  # operation encrypted with ENC(Xmsg,DH(PKapr,SKbsr))
}

struct OperationStatusQ @0x865d80cea70d884a {
    nodeStatus              @0  :NodeStatus;            # Optional: node status update about the statusq sender
}

struct OperationStatusA @0xb306f407fa812a55 {
    nodeStatus              @0  :NodeStatus;            # Optional: returned node status
    senderInfo              @1  :SenderInfo;            # Optional: info about StatusQ sender from the perspective of the replier
}

struct OperationValidateDialInfo @0xbc716ad7d5d060c8 {
    dialInfo                @0  :DialInfo;              # dial info to use for the receipt
    receipt                 @1  :Data;                  # receipt to return to dial info to prove it is reachable
    redirect                @2  :Bool;                  # request a different node do the validate
}

struct OperationReturnReceipt @0xeb0fb5b5a9160eeb {
    receipt                 @0  :Data;                  # receipt being returned to its origin
}

struct OperationFindNodeQ @0xfdef788fe9623bcd {    
    nodeId                  @0  :TypedKey;              # node id to locate
    capabilities            @1  :List(Capability);      # required capabilities returned peers must have
}

struct OperationFindNodeA @0xa84cf2fb40c77089 {
    peers                   @0  :List(PeerInfo);        # returned 'closer peer' information
}

struct OperationRoute @0x96741859ce6ac7dd {
    safetyRoute             @0  :SafetyRoute;           # where this should go
    operation               @1  :RoutedOperation;       # the operation to be routed
}

struct OperationAppCallQ @0xade67b9f09784507 {
    message                 @0  :Data;                  # opaque request to application
}

struct OperationAppCallA @0xf7c797ac85f214b8 {
    message                 @0  :Data;                  # opaque response from application
}

struct OperationAppMessage @0x9baf542d81b411f5 {
    message                 @0  :Data;                  # opaque message to application
}

struct SubkeyRange @0xf592dac0a4d0171c {
    start                   @0  :Subkey;                # the start of a subkey range
    end                     @1  :Subkey;                # the end of a subkey range
}
    
struct SignedValueData @0xb4b7416f169f2a3d {
    seq                     @0  :ValueSeqNum;           # sequence number of value
    data                    @1  :Data;                  # value or subvalue contents
    writer                  @2  :PublicKey;             # the public key of the writer
    signature               @3  :Signature;             # signature of data at this subkey, using the writer key (which may be the same as the owner key)
                                                        # signature covers:
                                                        #  * ownerKey
                                                        #  * subkey
                                                        #  * sequence number
                                                        #  * data
                                                        # signature does not need to cover schema because schema is validated upon every set
                                                        # so the data either fits, or it doesn't.
}

struct SignedValueDescriptor @0xe7911cd3f9e1b0e7 {
    owner                   @0  :PublicKey;             # the public key of the owner
    schemaData              @1  :Data;                  # the schema data
                                                        # Changing this after key creation is not supported as it would change the dht key
    signature               @2  :Signature;             # Schema data is signed by ownerKey and is verified both by set and get operations
}


struct OperationGetValueQ @0xf88a5b6da5eda5d0 {
    key                     @0  :TypedKey;              # DHT Key = Hash(ownerKeyKind) of: [ ownerKeyValue, schema ]
    subkey                  @1  :Subkey;                # the index of the subkey
    wantDescriptor          @2  :Bool;                  # whether or not to include the descriptor for the key
}


struct OperationGetValueA @0xd896bb46f2e0249f {
    value                   @0  :SignedValueData;       # optional: the value if successful, or if unset, no value returned
    peers                   @1  :List(PeerInfo);        # returned 'closer peer' information on either success or failure
    descriptor              @2  :SignedValueDescriptor; # optional: the descriptor if requested if the value is also returned
}

struct OperationSetValueQ @0xbac06191ff8bdbc5 {         
    key                     @0  :TypedKey;              # DHT Key = Hash(ownerKeyKind) of: [ ownerKeyValue, schema ]
    subkey                  @1  :Subkey;                # the index of the subkey
    value                   @2  :SignedValueData;       # value or subvalue contents (older or equal seq number gets dropped)
    descriptor              @3  :SignedValueDescriptor; # optional: the descriptor if needed
}

struct OperationSetValueA @0x9378d0732dc95be2 {
    set                     @0  :Bool;                  # true if the set was close enough to be set
    value                   @1  :SignedValueData;       # optional: the current value at the key if the set seq number was lower or equal to what was there before
    peers                   @2  :List(PeerInfo);        # returned 'closer peer' information on either success or failure
}

struct OperationWatchValueQ @0xf9a5a6c547b9b228 {
    key                     @0  :TypedKey;              # key for value to watch
    subkeys                 @1  :List(SubkeyRange);     # subkey range to watch (up to 512 subranges), if empty, watch everything
    expiration              @2  :UInt64;                # requested timestamp when this watch will expire in usec since epoch (can be return less, 0 for max)
    count                   @3  :UInt32;                # requested number of changes to watch for (0 = cancel, 1 = single shot, 2+ = counter, UINT32_MAX = continuous)
    watcher                 @4  :PublicKey;             # the watcher performing the watch, can be the owner or a schema member
    signature               @5  :Signature;             # signature of the watcher, must be one of the schema members or the key owner. signature covers: key, subkeys, expiration, count
}

struct OperationWatchValueA @0xa726cab7064ba893 {
    expiration              @0  :UInt64;                # timestamp when this watch will expire in usec since epoch (0 if watch failed)
    peers                   @1  :List(PeerInfo);        # returned list of other nodes to ask that could propagate watches
}

struct OperationValueChanged @0xd1c59ebdd8cc1bf6 {
    key                     @0  :TypedKey;              # key for value that changed
    subkeys                 @1  :List(SubkeyRange);     # subkey range that changed (up to 512 ranges at a time)
    count                   @2  :UInt32;                # remaining changes left (0 means watch has expired)
    value                   @3  :SignedValueData;       # first value that changed (the rest can be gotten with getvalue)
}

struct OperationSupplyBlockQ @0xadbf4c542d749971 {
    blockId                 @0  :TypedKey;              # hash of the block we can supply
}

struct OperationSupplyBlockA @0xf003822e83b5c0d7 {
    expiration              @0  :UInt64;                # when the block supplier entry will need to be refreshed, or 0 if not successful
    peers                   @1  :List(PeerInfo);        # returned 'closer peer' information if not successful       
}

struct OperationFindBlockQ @0xaf4353ff004c7156 {
    blockId                 @0  :TypedKey;              # hash of the block to locate
}

struct OperationFindBlockA @0xc51455bc4915465d {
    data                    @0  :Data;                  # Optional: the actual block data if we have that block ourselves
                                                        # null if we don't have a block to return
    suppliers               @1  :List(PeerInfo);        # returned list of suppliers if we have them
    peers                   @2  :List(PeerInfo);        # returned 'closer peer' information 
}

struct OperationSignal @0xd4f94f2a5d207e49 {
    union {
        holePunch           @0  :SignalInfoHolePunch;
        reverseConnect      @1  :SignalInfoReverseConnect;
    }
}

enum TunnelEndpointMode @0xef06f4c29beb7458 {
    raw                     @0;                         # raw tunnel
    turn                    @1;                         # turn tunnel
}

enum TunnelError @0xb82c6bfb1ec38c7c {
    badId                   @0;                         # Tunnel ID was rejected
    noEndpoint              @1;                         # Endpoint was unreachable
    rejectedMode            @2;                         # Endpoint couldn't provide mode
    noCapacity              @3;                         # Endpoint is full
}

struct TunnelEndpoint @0xc2602aa983cc337d {
    mode                    @0  :TunnelEndpointMode;    # what kind of endpoint this is
    description             @1  :Text;                  # endpoint description (TODO)
}

struct FullTunnel @0x9821c3dc75373f63 {
    id                      @0  :TunnelID;              # tunnel id to use everywhere
    timeout                 @1  :UInt64;                # duration from last data when this expires if no data is sent or received
    local                   @2  :TunnelEndpoint;        # local endpoint
    remote                  @3  :TunnelEndpoint;        # remote endpoint
}

struct PartialTunnel @0x827a7ebc02be2fc8 {
    id                      @0  :TunnelID;              # tunnel id to use everywhere
    timeout                 @1  :UInt64;                # timestamp when this expires if not completed
    local                   @2  :TunnelEndpoint;        # local endpoint
}

struct OperationStartTunnelQ @0xa9c49afce44187af {
    id                      @0  :TunnelID;              # tunnel id to use everywhere
    localMode               @1  :TunnelEndpointMode;    # what kind of local endpoint mode is being requested
    depth                   @2  :UInt8;                 # the number of nodes in the tunnel
}

struct OperationStartTunnelA @0x818162e4cc61bf1e {
    union {
        partial             @0  :PartialTunnel;         # the first half of the tunnel
        error               @1  :TunnelError;           # if we didn't start the tunnel, why not
    }
}

struct OperationCompleteTunnelQ @0xe978594588eb950b {
    id                      @0  :TunnelID;              # tunnel id to use everywhere
    localMode               @1  :TunnelEndpointMode;    # what kind of local endpoint mode is being requested
    depth                   @2  :UInt8;                 # the number of nodes in the tunnel
    endpoint                @3  :TunnelEndpoint;        # the remote endpoint to complete
}

struct OperationCompleteTunnelA @0x84090791bb765f2a {
    union {
        tunnel              @0  :FullTunnel;            # the tunnel description
        error               @1  :TunnelError;           # if we didn't complete the tunnel, why not
    }
}

struct OperationCancelTunnelQ @0xae2811ae0a003738 {
    id                      @0  :TunnelID;              # the tunnel id to cancel
}

struct OperationCancelTunnelA @0xbba23c992eff97bc {
    union {
        tunnel              @0  :TunnelID;              # the tunnel id that was cancelled
        error               @1  :TunnelError;           # if we couldn't cancel, why not
    }
}

# Things that want an answer
struct Question @0xd8510bc33492ef70 {
    respondTo :union {
        sender              @0  :Void;                  # sender
        privateRoute        @1  :PrivateRoute;          # embedded private route to be used for reply
    }
    detail :union {
        # Direct operations
        statusQ             @2  :OperationStatusQ;
        findNodeQ           @3  :OperationFindNodeQ;
        
        # Routable operations
        appCallQ            @4  :OperationAppCallQ;
        getValueQ           @5  :OperationGetValueQ;
        setValueQ           @6  :OperationSetValueQ;
        watchValueQ         @7  :OperationWatchValueQ;
        # #[cfg(feature="unstable-blockstore")]
        # supplyBlockQ        @8  :OperationSupplyBlockQ;
        # findBlockQ          @9  :OperationFindBlockQ;
        
        # Tunnel operations
        # #[cfg(feature="unstable-tunnels")]
        # startTunnelQ        @10 :OperationStartTunnelQ;
        # completeTunnelQ     @11 :OperationCompleteTunnelQ;
        # cancelTunnelQ       @12 :OperationCancelTunnelQ; 
    }
}

# Things that don't want an answer
struct Statement @0x990e20828f404ae1 {
    detail :union {
        # Direct operations
        validateDialInfo    @0  :OperationValidateDialInfo;
        route               @1  :OperationRoute;
        
        # Routable operations
        signal              @2  :OperationSignal;
        returnReceipt       @3  :OperationReturnReceipt;
        appMessage          @4  :OperationAppMessage;
        valueChanged        @5  :OperationValueChanged;
    }
}

# Things that are answers
struct Answer @0xacacb8b6988c1058 {
    detail :union {
        # Direct operations
        statusA             @0  :OperationStatusA;
        findNodeA           @1  :OperationFindNodeA;
        
        # Routable operations
        appCallA            @2  :OperationAppCallA;
        getValueA           @3  :OperationGetValueA;
        setValueA           @4  :OperationSetValueA;
        watchValueA         @5  :OperationWatchValueA;

        # #[cfg(feature="unstable-blockstore")]
        #supplyBlockA        @6  :OperationSupplyBlockA; 
        #findBlockA          @7  :OperationFindBlockA;
    
        # Tunnel operations
        # #[cfg(feature="unstable-tunnels")]
        # startTunnelA        @8  :OperationStartTunnelA;
        # completeTunnelA     @9  :OperationCompleteTunnelA;
        # cancelTunnelA       @10  :OperationCancelTunnelA;
    }
}

struct Operation @0xbf2811c435403c3b {
    opId                    @0  :UInt64;                # Random RPC ID. Must be random to foil reply forgery attacks. 
    senderPeerInfo          @1  :PeerInfo;              # (optional) PeerInfo for the sender to be cached by the receiver.
    targetNodeInfoTs        @2  :UInt64;                # Timestamp the sender believes the target's node info to be at or zero if not sent
    kind :union {
        question            @3  :Question;
        statement           @4  :Statement;
        answer              @5  :Answer;
    }
}
