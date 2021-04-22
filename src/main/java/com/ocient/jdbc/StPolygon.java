package com.ocient.jdbc;

import java.util.List;
public class StPolygon
{
    private final List<StPoint> exterior;
	private final List<List<StPoint>> holes;

	public StPolygon(final List<StPoint> exterior, final List<List<StPoint>> holes)
	{
		this.exterior = exterior;
        this.holes = holes;
	}

    public List<StPoint> getExterior(){
        return exterior; 
    }
    
    public List<List<StPoint>> getHoles(){
        return holes; 
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
}
