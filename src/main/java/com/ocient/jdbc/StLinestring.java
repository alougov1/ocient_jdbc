package com.ocient.jdbc;

import java.util.List;

import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class StLinestring
{
	private final List<StPoint> points;

	public StLinestring(final List<StPoint> points)
	{
		this.points = points;
	}

	@Override
	public String toString()
	{
		if (points == null || points.size() == 0) {
			return "LINESTRING EMPTY";
		}
		final StringBuilder str = new StringBuilder();
		str.append("LINESTRING(");
		for (int i = 0; i < points.size(); i++) {
			StPoint point = points.get(i);
			str.append(point.getX());
			str.append(" ");
			str.append(point.getY());
			if(i < points.size() - 1) {
				str.append(", ");
			}
		}
		str.append(")");
		return str.toString();
	}

	public void writeXML(Document doc, Element docElement, String name)
	{
		Element placemark = doc.createElement("Placemark");
		docElement.appendChild(placemark);

		Element lineName = doc.createElement("name");
		lineName.appendChild(doc.createTextNode(name));
		placemark.appendChild(lineName);        

		Element lineStyle = doc.createElement("styleUrl");
		lineStyle.appendChild(doc.createTextNode("__managed_style_02DBC6391B1971D9081A"));
		placemark.appendChild(lineStyle);

		Element line = doc.createElement("LineString");
		placemark.appendChild(line);

		Attr lineID = doc.createAttribute("id");
		lineID.setValue(name);
		line.setAttributeNode(lineID);

		Element coords = doc.createElement("coordinates");
		String coordinates = "";
		for(StPoint point : points) {
			coordinates += point.getX() + "," + point.getY() + " ";
		}
		coords.appendChild(doc.createTextNode(coordinates));
		line.appendChild(coords);
	}
}
