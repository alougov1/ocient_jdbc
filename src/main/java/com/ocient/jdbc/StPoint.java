package com.ocient.jdbc;

import java.util.Objects; 
public class StPoint
{
	private final double lon;
	private final double lat;

	// For normalizing, necessary to keep member variables final 
	private double tempLon; 
	private double tempLat; 

	public StPoint(final double lon, final double lat)
	{
		tempLon = lon;
		tempLat = lat; 
		normalize(); 
		
		this.lon = tempLon;
		this.lat = tempLat;
	}

	public double getLatitude()
	{
		return lat;
	}

	public double getLongitude()
	{
		return lon;
	}

	public double getX()
	{
		return lon;
	}

	public double getY()
	{
		return lat;
	}

	@Override
	public String toString()
	{
		if (Double.isInfinite(lat) || Double.isInfinite(lon))
		{
			return "POINT EMPTY";
		}
		return "POINT(" + lon + " " + lat + ")";
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true; 
		}
		
		if (o == null || getClass() != o.getClass()) {
			return false; 
		}

		StPoint other = (StPoint) o;
		return (this.lon == other.lon) && (this.lat == other.lat); 
	}

	private void normalize(){ 
		// See stPoint.h::makeSelfValidAndNormal() 
		while (tempLon < -180) {
			tempLon += 360; 
		}

		while (tempLon >= 180) {
			tempLon -= 360; 
		}

		if (tempLat < -90) {
			tempLat = -180 - lat;
			tempLon += 180; 
			normalize(); 
			return; 
		}

		if (tempLat > 90) {
			tempLat = 180 - tempLat;
			tempLon += 180;
			normalize(); 
			return; 
		}

		double tolerance = 1e-6; 
		if (Math.abs(90 - Math.abs(tempLat)) < tolerance) {
			tempLon = 0;
			if (tempLat > 0) {
				tempLat = 90;
			} else {
				tempLat = -90; 
			}
		}
	}
	
	@Override
	public int hashCode(){
		return Objects.hash(lon, lat); 
	}
}
