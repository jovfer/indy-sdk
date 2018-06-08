package org.hyperledger.indy.sdk.wallet;

import org.hyperledger.indy.sdk.ErrorCode;
import org.hyperledger.indy.sdk.IndyException;

/**
 * Exception thrown if wallet input has invalid structure (currently used in wallet import)
 */
public class WalletStructureException extends IndyException
{
	private static final long serialVersionUID = 1829076830401150667L;
	private final static String message = "Structure error occurred during wallet operation.";

	/**
	 * Initializes a new WalletStructureException.
	 */
	public WalletStructureException()
    {
    	super(message, ErrorCode.WalletStructureError.value());
    }
}