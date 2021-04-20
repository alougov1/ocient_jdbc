package com.ocient.jdbc;

import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

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
		if(Double.isInfinite(lat) && Double.isInfinite(lon)) {
			return "POINT EMPTY";
		}
		return "(" + lat + ", " + lon + ")";
	}

	public void writeXML(Document doc, Element docElement, String name)
	{
		Element placemark = doc.createElement("Placemark");
		docElement.appendChild(placemark);

		Element pointName = doc.createElement("name");
		pointName.appendChild(doc.createTextNode(name));
		placemark.appendChild(pointName);
		
		Element point = doc.createElement("Point");
		placemark.appendChild(point);

		Element coords = doc.createElement("coordinates");
		coords.appendChild(doc.createTextNode(lon + "," + lat));
		point.appendChild(coords);
	}
}
