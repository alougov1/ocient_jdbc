package com.ocient.jdbc;

import java.sql.Time;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.TimeZone;

public class XGTime extends Time
{

	/** */
	private static final long serialVersionUID = -6636929210798184587L;

	private static ThreadLocal<SimpleDateFormat> threadLocalSDF = new ThreadLocal<SimpleDateFormat>(){
		@Override protected SimpleDateFormat initialValue(){
			SimpleDateFormat newSDF = new SimpleDateFormat("HH:mm:ss");
			newSDF.setTimeZone(TimeZone.getTimeZone("UTC"));
			final GregorianCalendar cal = new GregorianCalendar();
			cal.setGregorianChange(new java.util.Date(Long.MIN_VALUE));
			cal.setTimeZone(TimeZone.getTimeZone("UTC"));
			newSDF.setCalendar(cal);
			return newSDF;
		}
	};

	public static Date from(final Instant instant)
	{
		final XGTime retval = new XGTime(instant.toEpochMilli());
		retval.setNanos(instant.getNano());
		return retval;
	}

	@Deprecated
	public static long parse(final String s)
	{
		try
		{
			final DateFormat format = DateFormat.getDateInstance();
			format.setTimeZone(TimeZone.getDefault());
			final GregorianCalendar cal = new GregorianCalendar();
			cal.setGregorianChange(new java.util.Date(Long.MIN_VALUE));
			cal.setTimeZone(TimeZone.getDefault());
			format.setCalendar(cal);
			final java.util.Date date = format.parse(s);
			return date.getTime();
		}
		catch (final Exception e)
		{
			return 0;
		}
	}

	@Deprecated
	public static long UTC(final int year, final int month, final int date, final int hrs, final int min, final int sec)
	{
		final GregorianCalendar cal = new GregorianCalendar(year + 1900, month, date, hrs, min, sec);
		cal.setTimeZone(TimeZone.getTimeZone("UTC"));
		cal.setGregorianChange(new java.util.Date(Long.MIN_VALUE));
		return cal.getTime().getTime();
	}

	public static Time valueOf(final String s)
	{
		return new XGTime(java.sql.Time.valueOf(s));
	}

	private int nanos;

	@Deprecated
	public XGTime(final int hour, final int minute, final int second)
	{
		super(hour, minute, second);
	}

	public XGTime(final long time)
	{
		super(time);
		final long seconds = time / 1000;
		final int ms = (int) (time - seconds * 1000);
		setNanos(ms * 1000000);
	}

	public XGTime(final Time t)
	{
		super(t.getTime());
		final long time = t.getTime();
		final long seconds = time / 1000;
		final int ms = (int) (time - seconds * 1000);
		setNanos(ms * 1000000);
	}

	public XGTime addMs(final int ms)
	{
		final int fractionPastMs = getNanos() - getNanos() / 1000000 * 1000000;
		final XGTime retval = new XGTime(getTime() + ms);
		retval.setNanos(retval.getNanos() + fractionPastMs);
		return retval;
	}

	@Override
	public boolean equals(final Object obj)
	{
		if (obj instanceof XGTime)
		{
			return getTime() == ((XGTime) obj).getTime() && getNanos() == ((XGTime) obj).getNanos();
		}

		if (obj instanceof java.util.Date)
		{
			return getTime() == ((java.util.Date) obj).getTime();
		}

		return false;
	}

	@Override
	public int hashCode()
	{
		return Long.hashCode(getTime()) + getNanos();
	}

	@Override
	@Deprecated
	public int getDate()
	{
		final SimpleDateFormat sdf = new SimpleDateFormat("d");
		sdf.setTimeZone(TimeZone.getDefault());
		final GregorianCalendar cal = new GregorianCalendar();
		cal.setGregorianChange(new java.util.Date(Long.MIN_VALUE));
		cal.setTimeZone(TimeZone.getDefault());
		sdf.setCalendar(cal);
		return Integer.parseInt(sdf.format(this));
	}

	@Override
	@Deprecated
	public int getDay()
	{
		final SimpleDateFormat sdf = new SimpleDateFormat("u");
		sdf.setTimeZone(TimeZone.getDefault());
		final GregorianCalendar cal = new GregorianCalendar();
		cal.setGregorianChange(new java.util.Date(Long.MIN_VALUE));
		cal.setTimeZone(TimeZone.getDefault());
		sdf.setCalendar(cal);
		int retval = Integer.parseInt(sdf.format(this));
		if (retval == 7)
		{
			retval = 0;
		}

		return retval;
	}

	@Override
	@Deprecated
	public int getMonth()
	{
		final SimpleDateFormat sdf = new SimpleDateFormat("M");
		sdf.setTimeZone(TimeZone.getDefault());
		final GregorianCalendar cal = new GregorianCalendar();
		cal.setGregorianChange(new java.util.Date(Long.MIN_VALUE));
		cal.setTimeZone(TimeZone.getDefault());
		sdf.setCalendar(cal);
		return Integer.parseInt(sdf.format(this)) - 1;
	}

	int getNanos()
	{
		return nanos;
	}

	@Override
	@Deprecated
	public int getTimezoneOffset()
	{
		return (int) ((getTime() - UTC(getYear(), getMonth(), getDate(), getHours(), getMinutes(), getSeconds())) / (60 * 1000));
	}

	@Override
	@Deprecated
	public int getYear()
	{
		final SimpleDateFormat sdf = new SimpleDateFormat("yyyy");
		sdf.setTimeZone(TimeZone.getDefault());
		final GregorianCalendar cal = new GregorianCalendar();
		cal.setGregorianChange(new java.util.Date(Long.MIN_VALUE));
		cal.setTimeZone(TimeZone.getDefault());
		sdf.setCalendar(cal);
		return Integer.parseInt(sdf.format(this)) - 1900;
	}

	@Override
	@Deprecated
	public void setDate(final int date)
	{
		final SimpleDateFormat sdf = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss.SSS");
		sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
		final GregorianCalendar cal = new GregorianCalendar();
		cal.setGregorianChange(new java.util.Date(Long.MIN_VALUE));
		cal.setTimeZone(TimeZone.getTimeZone("UTC"));
		sdf.setCalendar(cal);
		final String current = sdf.format(this);
		final String newVal = current.substring(0, 8) + String.format("%02d", date) + current.substring(10);
		setTime(parse(newVal));
	}

	@Override
	@Deprecated
	public void setMonth(final int month)
	{
		final SimpleDateFormat sdf = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss.SSS");
		sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
		final GregorianCalendar cal = new GregorianCalendar();
		cal.setGregorianChange(new java.util.Date(Long.MIN_VALUE));
		cal.setTimeZone(TimeZone.getTimeZone("UTC"));
		sdf.setCalendar(cal);
		final String current = sdf.format(this);
		final String newVal = current.substring(0, 5) + String.format("%02d", month + 1) + current.substring(7);
		setTime(parse(newVal));
	}

	void setNanos(final int nanos)
	{
		// We have to update time as well, unlike with timestamp
		// Get milliseconds
		final int ms = nanos / 1000000;

		// Time needs to be set to this much past a second boundary
		setTime(getTime() / 1000 * 1000 + ms);

		this.nanos = nanos;
	}

	@Override
	@Deprecated
	public void setYear(final int year)
	{
		final SimpleDateFormat sdf = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss.SSS");
		sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
		final GregorianCalendar cal = new GregorianCalendar();
		cal.setGregorianChange(new java.util.Date(Long.MIN_VALUE));
		cal.setTimeZone(TimeZone.getTimeZone("UTC"));
		sdf.setCalendar(cal);
		final String current = sdf.format(this);
		final String newVal = String.format("%04d", year + 1900) + current.substring(4);
		setTime(parse(newVal));
	}

	@Override
	@Deprecated
	public String toGMTString()
	{
		final SimpleDateFormat sdf = new SimpleDateFormat("d MMM yyyy HH:mm:ss");
		sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
		final GregorianCalendar cal = new GregorianCalendar();
		cal.setGregorianChange(new java.util.Date(Long.MIN_VALUE));
		cal.setTimeZone(TimeZone.getTimeZone("UTC"));
		sdf.setCalendar(cal);
		return sdf.format(this) + " GMT";
	}

	@Override
	@Deprecated
	public String toLocaleString()
	{
		final DateFormat format = DateFormat.getDateInstance();
		format.setTimeZone(TimeZone.getDefault());
		final GregorianCalendar cal = new GregorianCalendar();
		cal.setGregorianChange(new java.util.Date(Long.MIN_VALUE));
		cal.setTimeZone(TimeZone.getDefault());
		format.setCalendar(cal);
		return format.format(this);
	}

	// Always returns //UTC string
	@Override
	public String toString()
	{	
		return threadLocalSDF.get().format(this) + "." + String.format("%09d", getNanos());
	}
}
