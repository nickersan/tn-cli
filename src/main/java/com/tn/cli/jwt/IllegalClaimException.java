package com.tn.cli.jwt;

public class IllegalClaimException extends RuntimeException
{
  public IllegalClaimException(String message)
  {
    super(message);
  }
}
