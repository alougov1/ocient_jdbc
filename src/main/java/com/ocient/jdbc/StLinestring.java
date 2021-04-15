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
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }

        if (o == null || getClass() != o.getClass()) {
            return false; 
        }

        StLinestring other = (StLinestring) o;

        // Exact same points 
        if (other.points.equals(this.points)) {
            return true; 
        }

        // Same points, but in reverse order 
        if (other.points.size() == this.points.size()) {
            int numPoints = this.points.size(); 
            for (int i = 0; i < numPoints; ++i) {
                StPoint mPoint = this.points.get(i); 
                StPoint oPoint = other.points.get(numPoints - 1 - i); 
                if (!mPoint.equals(oPoint)) {
                    return false; 
                }
            }
            return true; 
        }
        return false;
    }

	@Override
	public int hashCode(){
        int hash = 0;
        for (StPoint p : points) {
            hash += p.hashCode(); 
        }
        return hash; 
	}}
