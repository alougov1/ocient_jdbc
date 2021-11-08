package com.ocient.cli;

/*
 * An exception thrown by CLI code if a parse error is encountered.
 */
public class ParseExecption extends RuntimeException
{
    // Constructor to wrap another throwable as the cause
    public ParseExecption(String errorMessage, Throwable cause)
    {
        super(errorMessage, cause);
    }

    // Constructor with a specified error message
    public ParseExecption(String errorMessage)
    {
        super(errorMessage);
    }
}
