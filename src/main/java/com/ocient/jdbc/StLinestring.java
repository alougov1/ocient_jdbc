package com.ocient.jdbc;

import java.util.List;
public class StLinestring
{
	private final List<StPoint> points;

	public StLinestring(final List<StPoint> points)
	{
		this.points = points;
	}

    public List<StPoint> getPoints(){
        return points; 
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
}
