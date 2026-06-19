package com.tn.cli;

public class MissingOptionException extends RuntimeException
{
  public MissingOptionException(String message)
  {
    super(message);
  }
}
