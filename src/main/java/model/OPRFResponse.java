package model;

import org.apache.milagro.amcl.BLS461.FP12;

public class OPRFResponse {

	private FP12 y;
	private String ssid;
	private long time;

	public OPRFResponse(){
		
	}
	
	public OPRFResponse(FP12 y, String ssid, long time) {
//public OPRFResponse(FP12 y) {
		super();
		this.y = y;
		this.ssid = ssid;
		this.time = time;
	}

	public String getSsid() {
		return ssid;
	}

	public void setSsid(String ssid) {
		this.ssid = ssid;
	}

	public void setY(FP12 y) {
		this.y = y;
	}

	public FP12 getY() {
		return y;
	}

	public long getTime() {return time;}

	public void setTime(long time) {this.time = time;}

}
