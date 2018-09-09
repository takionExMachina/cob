function addDetector(address detectorAddress) public returns (uint detectorID)
{
	detectorID = detectors.length++;
	Detector storage detector = detectors[detectorID];
	Detector.authority = detectorAddress;
	emit DetectorAdded(detectorID, detectorAddress);
}

function registerCA(address caAddress, string caName) public returns (uint caID){
	caID = cas.length++;
	CertificateAuthority storage ca = cas[caID];
	ca.caOwner = caAddress;
	ca.caName = caName;
	emit CAAdded(caID, caAddress, caName);
}

function registerDCP(string identifier, string data, string certHash, uint certExpiry, address CA) public returns (uint dcpID)
{
	dcpID = dcps.length++;
	DomainCertificatePolicy storage dcp = dcps[dcpID]
	dcp.identifier = identifier;
	dcp.owner = msg.sender;
	dcp.data = data;
	dcp.CA = CA;
	dcp.certHash = certHash;
	dcp.certExpiry = certExpiry;
	emit DCPAdded(dcpID, msg.sender, identifier, data, certHash,
certExpiry, CA);
}

function signRP(uint dcpID, uint expiry) public returns (uint signatureID)
{
	if(dcps[dcpID].CA == msg.sender){
		signatureID = rps.length++;
		ReactionPolicy storage rp = rps[signatureID];
		rp.CA = dcps[dcpID].CA;
		rp.signer = msg.sender;
		rp.attributeID = dcpID;
		rp.expiry = expiry;
		emit RPSigned(signatureID, msg.sender, rp.CA, dcpID,
expiry);
	}
}

function revokeSignature(uint reactionPolicyID, string certHash, address
caAddress, uint detectorIndex) public returns (uint revocationID)
{
	if(rps[reactionPolicyID].signer == msg.sender ||
detectors[detectorIndex].authority == msg.sender)
	{	
		revocationID = revocations.length++;
		Revocation storage revocation = revocations[revocationID];
		revocation.rpID = reactionPolicyID;
		revocation.certHash = certHash;
		revocation.CA = caAddress;
		emit SignatureRevoked(revocationID, certHash,
reactionPolicyID, caAddress);
	}
}

function blacklistCA(uint caIndex, uint detectorIndex) public 
{	
	if(detectors[detectorIndex].authority == msg.sender)
	{
		if(cas.length > 1)
		{
			cas[caIndex] = cas[cas.length-1];
			delete(cas[cas.length-1]);
		}
		cas.length--;
	}
	emit CABlacklisted(caIndex, detectorIndex);
}
