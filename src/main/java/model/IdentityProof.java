package model;

/*import com.google.protobuf.InvalidProtocolBufferException;
import eu.olympus.protos.serializer.Serializer;
import org.apache.commons.codec.binary.Base64;*/

/*import java.util.HashMap;
import java.util.Map;*/

public class IdentityProof {

	private String signature;
//	private Map<String, Attribute> attributes;

	public IdentityProof(){
	}

//	public IdentityProof(String signature, Map<String, Attribute> attributes) {
	public IdentityProof(String signature) {
		super();
		this.signature = signature;
//		this.attributes = attributes;
	}

/*	public IdentityProof(String idProof) throws InvalidProtocolBufferException {
		Serializer.IdentityProof protoIdProof= Serializer.IdentityProof.parseFrom(Base64.decodeBase64(idProof));
		this.signature=protoIdProof.getSignature();
		this.attributes=new HashMap<>();
		Map<String, Serializer.Attribute> protoAttr=protoIdProof.getAttributesMap();
		for (String attr:protoAttr.keySet()){
			this.attributes.put(attr,new Attribute(protoAttr.get(attr)));
		}
	}*/

	public Object getSignature() {
		return signature;
	}

	public void setSignature(String signature) {
		this.signature = signature;
	}

/*	public Map<String, Attribute> getAttributes() {
		return attributes;
	}

	public void setAttributes(Map<String, Attribute> attributes) {
		this.attributes = attributes;
	}*/

/*	@Override
	public String toString() {
		return Base64.encodeBase64String(toProto().toByteArray());
	}

	private Serializer.IdentityProof toProto(){
		Map<String, Serializer.Attribute> protoAttributes=new HashMap<>();
		for(String attrName:attributes.keySet())
			protoAttributes.put(attrName,attributes.get(attrName).toProto());
		return Serializer.IdentityProof.newBuilder()
				.setSignature(signature)
				.putAllAttributes(protoAttributes)
				.build();
	}*/

}


