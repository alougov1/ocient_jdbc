package com.ocient.jdbc;

import java.io.File;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.XMLConstants;

import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.ocient.jdbc.StPolygon;
import com.ocient.jdbc.StPoint;
import com.ocient.jdbc.StLinestring;

public class KML {
	private static String outputKMLFile = ""; //contains kml file location to output resultset to

    public static boolean KMLIsEmpty() {
        return outputKMLFile.isEmpty();
    }

    public static void setKML(String kmlFile) {
        outputKMLFile = kmlFile;
    }

    public static void genStyleMap(String color, int styleNum, Document doc, Element documentElement) {
		//generate 1st gx cascading style, used when object is not being hovered over
		Element gx1 = doc.createElement("gx:CascadingStyle");
		documentElement.appendChild(gx1);
		Attr gx1ID = doc.createAttribute("kml:id");
		gx1ID.setValue(styleNum + "A");
		gx1.setAttributeNode(gx1ID);
		Element gx1Style = doc.createElement("Style");
		gx1.appendChild(gx1Style);
		
		Element gx1IconStyle = doc.createElement("IconStyle"); //style of st_points
		gx1Style.appendChild(gx1IconStyle);
		Element gx1Icon = doc.createElement("Icon");
		gx1IconStyle.appendChild(gx1Icon);
		Element gx1Href = doc.createElement("href");
		gx1Icon.appendChild(gx1Href);
		gx1Href.appendChild(doc.createTextNode("https://earth.google.com/earth/rpc/cc/icon?color=" + color.substring(6) + color.substring(4,6) + color.substring(2,4) + "&id=2000&scale=4")); // link to placemark style
		
		Element gx1LineStyle = doc.createElement("LineStyle"); // style of st_linestring
		gx1Style.appendChild(gx1LineStyle);
		Element gx1LineColor = doc.createElement("color"); 
		gx1LineStyle.appendChild(gx1LineColor);
		gx1LineColor.appendChild(doc.createTextNode(color)); // lines determine polygon borders as well
		Element gx1LineWidth = doc.createElement("width");
		gx1LineStyle.appendChild(gx1LineWidth);
		gx1LineWidth.appendChild(doc.createTextNode("2"));
		
		Element gx1PolyStyle= doc.createElement("PolyStyle"); //style of st_polygon
		gx1Style.appendChild(gx1PolyStyle);
		Element gx1PolyColor = doc.createElement("color");
		gx1PolyStyle.appendChild(gx1PolyColor);
		gx1PolyColor.appendChild(doc.createTextNode("7f" + color.substring(2)));

		//generate 2nd gx cascading style used when object is highlighted/hovered over
		Element gx2 = doc.createElement("gx:CascadingStyle");
		documentElement.appendChild(gx2);
		Attr gx2ID = doc.createAttribute("kml:id");
		gx2ID.setValue(styleNum + "B");
		gx2.setAttributeNode(gx2ID);
		Element gx2Style = doc.createElement("Style");
		gx2.appendChild(gx2Style);
		
		Element gx2IconStyle = doc.createElement("IconStyle"); //style of st_point
		gx2Style.appendChild(gx2IconStyle);
		Element gx2Scale = doc.createElement("scale");
		gx2IconStyle.appendChild(gx2Scale);
		gx2Scale.appendChild(doc.createTextNode("1.2"));
		Element gx2Icon = doc.createElement("Icon");
		gx2IconStyle.appendChild(gx2Icon);
		Element gx2Href = doc.createElement("href");
		gx2Icon.appendChild(gx2Href);
		gx2Href.appendChild(doc.createTextNode("https://earth.google.com/earth/rpc/cc/icon?color=" + color.substring(6) + color.substring(4,6) + color.substring(2,4) + "&id=2000&scale=4")); // link to image for pointer to st_point
		
		Element gx2LineStyle = doc.createElement("LineStyle"); //style of st_linestring
		gx2Style.appendChild(gx2LineStyle);
		Element gx2LineColor = doc.createElement("color");
		gx2LineStyle.appendChild(gx2LineColor);
		gx2LineColor.appendChild(doc.createTextNode(color));
		Element gx2LineWidth = doc.createElement("width");
		gx2LineStyle.appendChild(gx2LineWidth);
		gx2LineWidth.appendChild(doc.createTextNode("3"));
		
		Element gx2PolyStyle= doc.createElement("PolyStyle"); //style of st_polygon
		gx2Style.appendChild(gx2PolyStyle);
		Element gx2PolyColor = doc.createElement("color");
		gx2PolyStyle.appendChild(gx2PolyColor);
		gx2PolyColor.appendChild(doc.createTextNode("7f" + color.substring(2)));

		//generate stylemap
		Element stylemap = doc.createElement("StyleMap"); //stylemap, switches between the normal and highlighted styles
		documentElement.appendChild(stylemap);
		Attr stylemapID = doc.createAttribute("id");
		stylemapID.setValue(Integer.toString(styleNum));
		stylemap.setAttributeNode(stylemapID);

		Element stylemapNormal = doc.createElement("Pair");
		stylemap.appendChild(stylemapNormal);
		Element normalKey = doc.createElement("key");
		stylemapNormal.appendChild(normalKey);
		normalKey.appendChild(doc.createTextNode("normal"));
		Element normalURL = doc.createElement("styleUrl");
		stylemapNormal.appendChild(normalURL);
		normalURL.appendChild(doc.createTextNode(styleNum + "A"));

		Element stylemapHighlight = doc.createElement("Pair");
		stylemap.appendChild(stylemapHighlight);
		Element highlightKey = doc.createElement("key");
		stylemapHighlight.appendChild(highlightKey);
		highlightKey.appendChild(doc.createTextNode("highlight"));
		Element highlightURL = doc.createElement("styleUrl");
		stylemapHighlight.appendChild(highlightURL);
		highlightURL.appendChild(doc.createTextNode(styleNum + "B"));
	}

	public static void outputGeospatial(final ResultSet rs) throws Exception {
		final ResultSetMetaData meta = rs.getMetaData();
        DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
		DocumentBuilder docBuilder = docFactory.newDocumentBuilder();

		Document doc = docBuilder.newDocument();
		//create kmlElement
		Element kmlElement = doc.createElement("kml");
		doc.appendChild(kmlElement);

		//kml Attributes, should never need to change
		Attr kmlAttrXMLNS = doc.createAttribute("xmlns");
		kmlAttrXMLNS.setValue("http://www.opengis.net/kml/2.2");
		kmlElement.setAttributeNode(kmlAttrXMLNS);

		Attr kmlAttrGX = doc.createAttribute("xmlns:gx");
		kmlAttrGX.setValue("http://www.google.com/kml/ext/2.2");
		kmlElement.setAttributeNode(kmlAttrGX);

		Attr kmlAttrKML = doc.createAttribute("xmlns:kml");
		kmlAttrKML.setValue("http://www.opengis.net/kml/2.2");
		kmlElement.setAttributeNode(kmlAttrKML);

		Attr kmlAttrAtom = doc.createAttribute("xmlns:atom");
		kmlAttrAtom.setValue("http://www.w3.org/2005/Atom");
		kmlElement.setAttributeNode(kmlAttrAtom);

		//create doc element
		Element documentElement = doc.createElement("Document");
		kmlElement.appendChild(documentElement);
		
		Attr docID = doc.createAttribute("id");
		docID.setValue("1SYf0ab5Z9uWomNsdRt1GbNfojQtUNfC6");
		documentElement.setAttributeNode(docID);

		Element name = doc.createElement("name");
		documentElement.appendChild(name);
		
		genStyleMap("ff0078F0",0,doc,documentElement);
		genStyleMap("ff14006E",1,doc,documentElement);
		genStyleMap("ff14F000",2,doc,documentElement);
		genStyleMap("ffFF78F0",3,doc,documentElement);
		genStyleMap("ff38FFFF",4,doc,documentElement);
		genStyleMap("ffF0FF14",5,doc,documentElement);
		genStyleMap("ff1478F0",6,doc,documentElement);
		genStyleMap("ff1400FF",7,doc,documentElement);
		genStyleMap("ff1478FF",8,doc,documentElement);
		genStyleMap("ff7882B4",9,doc,documentElement);

		int count = 0; //counts how many objects we've visited to get row/column count
		name.appendChild(doc.createTextNode("GIS")); //name of the GIS project

		while (rs.next())
		{
			final StringBuilder description = new StringBuilder("<![CDATA[<div>");
			for(int i = 1; i <= meta.getColumnCount(); i++) {
				final Object o = rs.getObject(i);
				if(!meta.getColumnTypeName(i).equals("ST_POINT") && !meta.getColumnTypeName(i).equals("ST_LINESTRING") && !meta.getColumnTypeName(i).equals("ST_POLYGON")) {
					if(i != 1) {
						description.append(", ");
					}
					description.append("<b>");
					description.append(meta.getColumnName(i));
					description.append("</b>: ");
					if(!rs.wasNull()) {
						description.append(o.toString());
					} else {
						description.append("null");
					}
				}
			}
			description.append("</div>");

			for (int i = 1; i <= meta.getColumnCount(); i++)
			{
				final Object o = rs.getObject(i);
				if (!rs.wasNull()) //must be a non-null geospatial object
				{
					if(meta.getColumnTypeName(i).equals("ST_POINT")) {
						((StPoint)(o)).writeXML(doc, documentElement, "col" + (i - 1) + "row" + (count), description.toString(), i - 1);
					} else if(meta.getColumnTypeName(i).equals("ST_LINESTRING")) {
						((StLinestring)(o)).writeXML(doc, documentElement, "col" + (i - 1) + "row" + (count), description.toString(), i - 1);
					} else if(meta.getColumnTypeName(i).equals("ST_POLYGON")) {
						((StPolygon)(o)).writeXML(doc, documentElement, "col" + (i - 1) + "row" + (count), description.toString(), i - 1);
					}
				}
			}
			count++;
		}
		
		//write the content into xml file
		TransformerFactory transformerFactory =  TransformerFactory.newInstance();
		transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
		transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
		Transformer transformer = transformerFactory.newTransformer();
		DOMSource source = new DOMSource(doc);

		StreamResult result =  new StreamResult(new File(outputKMLFile)); //prints result to target file
		transformer.transform(source, result);

		System.out.println("Outputed GIS results to " + outputKMLFile);
	}
}
