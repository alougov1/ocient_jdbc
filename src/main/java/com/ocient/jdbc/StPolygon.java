package com.ocient.jdbc;

import java.util.List;

import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class StPolygon
{
    private final List<StPoint> exterior;
	private final List<List<StPoint>> holes;

	public StPolygon(final List<StPoint> exterior, final List<List<StPoint>> holes)
	{
		this.exterior = exterior;
        this.holes = holes;
	}

	@Override
	public String toString()
	{
		if (exterior == null || exterior.size() == 0) {
            return "POLYGON EMPTY";
        }

        final StringBuilder str = new StringBuilder();

        str.append("POLYGON((");
        for (int i = 0; i < exterior.size(); i++) {
            StPoint point = exterior.get(i);
            str.append(point.getX());
            str.append(" ");
            str.append(point.getY());
            if(i < exterior.size() - 1) {
                str.append(", ");
            }
        }
        str.append(")");

        for(int i = 0; i < holes.size(); i++) {
            str.append(", ");
            List<StPoint> ring = holes.get(i);
            str.append("(");
            for (int j = 0; j < ring.size(); j++) {
                StPoint point = ring.get(j);
                str.append(point.getX());
                str.append(" ");
                str.append(point.getY());
                if(j < ring.size() - 1) {
                    str.append(", ");
                }
            }
            str.append(")");
        }

        str.append(")");

        return str.toString();
	}

    public void writeXML(Document doc, Element docElement, String name)
	{
        Element placemark = doc.createElement("Placemark");
		docElement.appendChild(placemark);

		Element polyName = doc.createElement("name");
		polyName.appendChild(doc.createTextNode(name));
		placemark.appendChild(polyName);        

		Element poly = doc.createElement("Polygon");
		placemark.appendChild(poly);

		Attr polyID = doc.createAttribute("id");
		polyID.setValue(name);
		poly.setAttributeNode(polyID);

		Element outer = doc.createElement("outerBoundaryIs");
        poly.appendChild(outer);
        Element linRing = doc.createElement("LinearRing");
        outer.appendChild(linRing);

		Element coords = doc.createElement("coordinates");
        String coordinates = "";
        for(StPoint point : exterior) {
            coordinates += point.getX() + "," + point.getY() + " ";
        }
        coords.appendChild(doc.createTextNode(coordinates));
        linRing.appendChild(coords);

        if(holes.size() > 0) {
            Element inner = doc.createElement("innerBoundaryIs");
            poly.appendChild(inner);
            for(List<StPoint> ring : holes) {
                Element linRingInner = doc.createElement("LinearRing");
                inner.appendChild(linRingInner);
                Element innerCoords = doc.createElement("coordinates");
                String innerCoordinates = "";
                for(StPoint point : ring) {
                    innerCoordinates += point.getX() + "," + point.getY() + " ";
                }
                innerCoords.appendChild(doc.createTextNode(innerCoordinates));
                linRingInner.appendChild(innerCoords);
            }
        }

	}
}
