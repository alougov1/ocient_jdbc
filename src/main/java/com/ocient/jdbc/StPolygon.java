package com.ocient.jdbc;

import java.util.List;
import java.util.Set;
import java.util.ArrayList;
import java.util.HashSet; 
// Java hashmaps don't support custom hash functions, so we hash a wrapper class 
class StRing 
{
    private final List<StPoint> points; 
    public StRing(List<StPoint> points) {
        this.points = points; 
    }
    // Not written in ideal Java but written to match stPolygon.h in case of changing logic 
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true; 
        }

        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        StRing other = (StRing) o; 
        if (other.points.size() != points.size()) {
            return false; 
        }

        if (points.size() == 0) {
            return true; 
        }

        if (points.size() == 1) {
            return points.get(0).equals(other.points.get(0)); 
        }

        if (points.equals(other.points)) {
            return true; 
        }

        int numPoints = points.size(); 
        if (!points.get(0).equals(points.get(numPoints - 1))) { 
            for (int i = 0; i < numPoints; ++i) {
                StPoint mPoint = points.get(i);
                StPoint oPoint = other.points.get(numPoints - 1 - i); 
                if (!mPoint.equals(oPoint)) {
                    return false; 
                }
            }

            return true; 
        }

        if (!other.points.get(0).equals(other.points.get(numPoints - 1))) {
            return false; 
        }

        // Both closed rings, but order may not be the same 
        int it = other.points.indexOf(points.get(0)); 
        while (it != -1) {
            int it2 = it;
            boolean ok = true; 
            for (int i = 0; i < points.size() - 1; ++i) {
                if (!points.get(i).equals(other.points.get(it2))) {
                    ok = false;
                    break; 
                }

                ++it2;
                if (it2 == numPoints) {
                    it2 = 1; 
                }
            }

            if (ok) {
                return true; 
            }

            it = other.points.subList(it + 1, numPoints).indexOf(points.get(0)); 
        }
        return false;
    }

    // Not written in ideal Java but written to match stPolygon.h: in case of changing logic 
    @Override 
    public int hashCode() {
        int hash = 0;
        if (points.size() == 0) {
            return 0;
        }

        if (points.size() == 1) {
            return points.get(0).hashCode(); 
        }

        if (!points.get(0).equals(points.get(points.size() - 1))) {
            for (StPoint p : points) {
                hash += p.hashCode();
            }
            return hash; 
        } 

        for (int i = 0; i < points.size() - 1; ++i) {
            hash += points.get(i).hashCode();
        }
        return hash; 
    }
}
public class StPolygon
{
    private final List<StPoint> exterior;
	private final List<List<StPoint>> holes;

    // Used for hashmap for order independent comparison only
    private StRing exteriorRing; 
    private List<StRing> holeRings; 

	public StPolygon(final List<StPoint> exterior, final List<List<StPoint>> holes)
	{
		this.exterior = exterior;
        this.holes = holes;

        this.exteriorRing = new StRing(exterior); 
        this.holeRings = new ArrayList<>(); 
        for (List<StPoint> hole : holes) { 
            holeRings.add(new StRing(hole)); 
        }
	}

    // Doesn't break encapsulation because members are final 
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

    @Override 
    public boolean equals(Object o) {
        if (this == o) {
            return true; 
        }

        if (o == null || getClass() != o.getClass()) {
            return false; 
        }

        StPolygon other = (StPolygon) o; 
        if (exterior.equals(other.exterior)) {
            if (holes.equals(other.holes)) {
                return true; 
            } else if (holes.size() == other.holes.size()) {
                Set<StRing> holeSet = new HashSet<>(); 
                for (StRing ring : other.holeRings) {
                    holeSet.add(ring); 
                }

                for (StRing ring : holeRings) {
                    if (!holeSet.contains(ring)) { 
                        return false; 
                    }
                }

                return true; 
            } else {
                // Same exterior but diff num holes 
                return false; 
            }
        } else if (holes.equals(other.holes)) {
            return exteriorRing.equals(other.exteriorRing); 
        } else if (exterior.size() == other.exterior.size() && holes.size() == other.holes.size()) {
            if (!exteriorRing.equals(other.exteriorRing)) {
                return false; 
            }   

            Set<StRing> holeSet = new HashSet<>(); 
            for (StRing ring : other.holeRings) {
                holeSet.add(ring); 
            }

            for (StRing ring : holeRings) {
                if (!holeSet.contains(ring)) { 
                    return false; 
                }
            }

            return true; 
        } else {
            return true; 
        }

    }
}
