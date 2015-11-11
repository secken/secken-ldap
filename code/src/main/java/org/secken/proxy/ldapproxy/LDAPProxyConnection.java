package org.secken.proxy.ldapproxy;

import org.apache.log4j.Logger;
import org.forgerock.opendj.ldap.Connection;
import org.forgerock.opendj.ldap.ConnectionFactory;
import org.forgerock.opendj.ldap.IntermediateResponseHandler;
import org.forgerock.opendj.ldap.LDAPClientContext;
import org.forgerock.opendj.ldap.LdapException;
import org.forgerock.opendj.ldap.LdapResultHandler;
import org.forgerock.opendj.ldap.ResultCode;
import org.forgerock.opendj.ldap.SearchResultHandler;
import org.forgerock.opendj.ldap.ServerConnection;
import org.forgerock.opendj.ldap.requests.AbandonRequest;
import org.forgerock.opendj.ldap.requests.AddRequest;
import org.forgerock.opendj.ldap.requests.BindRequest;
import org.forgerock.opendj.ldap.requests.CompareRequest;
import org.forgerock.opendj.ldap.requests.DeleteRequest;
import org.forgerock.opendj.ldap.requests.ExtendedRequest;
import org.forgerock.opendj.ldap.requests.ModifyDNRequest;
import org.forgerock.opendj.ldap.requests.ModifyRequest;
import org.forgerock.opendj.ldap.requests.SearchRequest;
import org.forgerock.opendj.ldap.requests.UnbindRequest;
import org.forgerock.opendj.ldap.responses.BindResult;
import org.forgerock.opendj.ldap.responses.CompareResult;
import org.forgerock.opendj.ldap.responses.ExtendedResult;
import org.forgerock.opendj.ldap.responses.Result;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.ResultHandler;
import org.secken.proxy.auth.SeckenAuthFactory;

public class LDAPProxyConnection implements ServerConnection<Integer> {

	SeckenAuthFactory authFacotry;
	Connection connection;
	private final LDAPClientContext clientContext;
	// private SaslServer saslServer;

	Logger logger = Logger.getLogger(LDAPProxyConnection.class);

	LDAPProxyConnection(LDAPClientContext clientContext, ConnectionFactory factory, SeckenAuthFactory authFacotry)
			throws LdapException {
		this.clientContext = clientContext;
		this.connection = factory.getConnection();
		this.authFacotry = authFacotry;
	}

	public void handleBind(Integer messageID, int version, final BindRequest request,
			IntermediateResponseHandler IntermediateResponseHandler,
			final LdapResultHandler<BindResult> resultHandler) {
		logger.debug("proxyFactory handleBind" + request);

		Promise<BindResult, LdapException> promise = connection.bindAsync(request);
		promise.thenOnResult(new ResultHandler<BindResult>() {

			public final void handleResult(final BindResult result) {

				if (result.getResultCode() == ResultCode.SASL_BIND_IN_PROGRESS) {
					resultHandler.handleResult(result);
				} else {
					LDAPProxySendResult sendResult = new LDAPProxySendResult(result, resultHandler);

					String dn[] = request.getName().split(",");
					String name[] = dn[0].split("=");

					authFacotry.StartAuth(name[1], sendResult);
				}
			}
		}).thenOnException(resultHandler);
	}

	public void handleSearch(Integer messageID, SearchRequest request,
			IntermediateResponseHandler IntermediateResponseHandler, SearchResultHandler searchResultHandler,
			LdapResultHandler<Result> resultHandler) {
		logger.debug("Recv search request, handle it.");

		Promise<Result, LdapException> promise = connection.searchAsync(request, searchResultHandler);
		promise.thenOnResult(resultHandler).thenOnException(resultHandler);

	}

	public void handleAdd(Integer messageID, AddRequest request,
			IntermediateResponseHandler IntermediateResponseHandler, LdapResultHandler<Result> resultHandler) {
		logger.debug("Recv add request, drop it.");
	}

	public void handleCompare(Integer requestContext, CompareRequest request,
			IntermediateResponseHandler intermediateResponseHandler, LdapResultHandler<CompareResult> resultHandler) {
		logger.debug("Recv compare request, drop it.");

	}

	public void handleDelete(Integer arg0, DeleteRequest arg1, IntermediateResponseHandler arg2,
			LdapResultHandler<Result> arg3) {
		logger.debug("Recv delete request, drop it.");

	}

	public <R extends ExtendedResult> void handleExtendedRequest(Integer requestContext, ExtendedRequest<R> request,
			IntermediateResponseHandler intermediateResponseHandler, LdapResultHandler<R> resultHandler) {
		logger.debug("Recv extended request, drop it.");
	}

	public void handleModify(Integer arg0, ModifyRequest arg1, IntermediateResponseHandler arg2,
			LdapResultHandler<Result> arg3) {
		System.out.println("Recv extended modify, drop it.");
	}

	public void handleModifyDN(Integer arg0, ModifyDNRequest arg1, IntermediateResponseHandler arg2,
			LdapResultHandler<Result> arg3) {
		logger.debug("Recv modify DN request, drop it.");
	}

	public void handleAbandon(Integer arg0, AbandonRequest arg1) {
		logger.debug("Recv abandon request, drop it.");
	}

	public void handleConnectionClosed(Integer arg0, UnbindRequest unbindRequest) {
		// final LocalizableMessage cancelReason =
		// INFO_CANCELED_BY_CLIENT_DISCONNECT.get();
		logger.debug("Connecction from " + clientContext.getPeerAddress() + " closed.");
		connection.close();
	}

	public void handleConnectionDisconnected(ResultCode arg0, String arg1) {
		// final LocalizableMessage cancelReason =
		// INFO_CANCELED_BY_CLIENT_DISCONNECT.get();
		logger.debug("Connecction from " + clientContext.getPeerAddress() + " disconnected.");
		connection.close();
	}

	public void handleConnectionError(Throwable arg0) {
		// final LocalizableMessage cancelReason =
		// INFO_CANCELED_BY_CLIENT_ERROR.get();
		logger.debug("Connecction from " + clientContext.getPeerAddress() + " error.");
		connection.close();
	}
}