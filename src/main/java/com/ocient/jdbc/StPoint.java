package com.ocient.jdbc;
public class StPoint
{
	private final double lon;
	private final double lat;

	public StPoint(final double lon, final double lat)
	{
		this.lon = lon;
		this.lat = lat;
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
}
