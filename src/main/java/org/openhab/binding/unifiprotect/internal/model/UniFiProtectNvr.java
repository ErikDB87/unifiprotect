/**
 * Copyright (c) 2010-2023 Contributors to the openHAB project
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 */
package org.openhab.binding.unifiprotect.internal.model;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Locale;
import java.util.NoSuchElementException;
import java.util.Optional;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.eclipse.jdt.annotation.Nullable;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.WWWAuthenticationProtocolHandler;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.openhab.binding.unifiprotect.internal.UniFiProtectIrMode;
import org.openhab.binding.unifiprotect.internal.UniFiProtectLcdMessage;
import org.openhab.binding.unifiprotect.internal.UniFiProtectRecordingMode;
import org.openhab.binding.unifiprotect.internal.UniFiProtectSmartDetectTypes;
import org.openhab.binding.unifiprotect.internal.UniFiProtectUtil;
import org.openhab.binding.unifiprotect.internal.event.UniFiProtectEventCache;
import org.openhab.binding.unifiprotect.internal.image.UniFiProtectImageHandler;
import org.openhab.binding.unifiprotect.internal.model.UniFiProtectStatus.SendStatus;
import org.openhab.binding.unifiprotect.internal.model.json.UniFiProtectEvent;
import org.openhab.binding.unifiprotect.internal.model.json.UniFiProtectJsonParser;
import org.openhab.binding.unifiprotect.internal.model.request.UniFiProtectAlertsRequest;
import org.openhab.binding.unifiprotect.internal.model.request.UniFiProtectAnonymousSnapshotRequest;
import org.openhab.binding.unifiprotect.internal.model.request.UniFiProtectBootstrapRequest;
import org.openhab.binding.unifiprotect.internal.model.request.UniFiProtectChimeRequest;
import org.openhab.binding.unifiprotect.internal.model.request.UniFiProtectEventsRequest;
import org.openhab.binding.unifiprotect.internal.model.request.UniFiProtectHdrModeRequest;
import org.openhab.binding.unifiprotect.internal.model.request.UniFiProtectHeatmapRequest;
import org.openhab.binding.unifiprotect.internal.model.request.UniFiProtectHighFpsModeRequest;
import org.openhab.binding.unifiprotect.internal.model.request.UniFiProtectIrModeRequest;
import org.openhab.binding.unifiprotect.internal.model.request.UniFiProtectLcdMessageRequest;
import org.openhab.binding.unifiprotect.internal.model.request.UniFiProtectLoginRequest;
import org.openhab.binding.unifiprotect.internal.model.request.UniFiProtectMotionDetectionRequest;
import org.openhab.binding.unifiprotect.internal.model.request.UniFiProtectPrivacyZoneRequest;
import org.openhab.binding.unifiprotect.internal.model.request.UniFiProtectRebootCameraRequest;
import org.openhab.binding.unifiprotect.internal.model.request.UniFiProtectRecordingModeRequest;
import org.openhab.binding.unifiprotect.internal.model.request.UniFiProtectSmartDetectRequest;
import org.openhab.binding.unifiprotect.internal.model.request.UniFiProtectSnapshotRequest;
import org.openhab.binding.unifiprotect.internal.model.request.UniFiProtectStatusLightRequest;
import org.openhab.binding.unifiprotect.internal.model.request.UniFiProtectStatusSoundsRequest;
import org.openhab.binding.unifiprotect.internal.model.request.UniFiProtectThumbnailRequest;
import org.openhab.binding.unifiprotect.internal.thing.UniFiProtectBaseThingConfig;
import org.openhab.binding.unifiprotect.internal.thing.UniFiProtectNvrThingConfig;
import org.openhab.binding.unifiprotect.internal.types.UniFiProtectCamera;
import org.openhab.binding.unifiprotect.internal.types.UniFiProtectNvrDevice;
import org.openhab.binding.unifiprotect.internal.types.UniFiProtectNvrUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The {@link UniFiProtectNvr}
 *
 * @author Joseph (Seaside) Hagberg - Initial contribution
 */
@NonNullByDefault
public class UniFiProtectNvr {

    private static final int IMAGE_MIN_SIZE = 200;
    private final Object tokenLock = new Object();

    /* All access must be guarded by "tokenLock" */
    private @Nullable String token;

    /* All access must be guarded by "this" */
    private volatile @Nullable UniFiProtectNvrDevice nvrDevice;

    /* All access must be guarded by "this" */
    private @Nullable UniFiProtectNvrUser nvrUser;
    private final UniFiProtectEventCache eventCache = new UniFiProtectEventCache();
    private final UniFiProtectCameraCache cameraInsightCache = new UniFiProtectCameraCache();

    private final HttpClient httpClient;
    private final Logger logger = LoggerFactory.getLogger(UniFiProtectNvr.class);

    private final UniFiProtectNvrThingConfig config;
    private final UniFiProtectJsonParser uniFiProtectJsonParser;

    public UniFiProtectNvr(UniFiProtectNvrThingConfig config) {
        this.config = config;
        httpClient = new HttpClient(new SslContextFactory(true));
        httpClient.setFollowRedirects(false);
        uniFiProtectJsonParser = new UniFiProtectJsonParser();
    }

    public boolean init() {
        try {
            httpClient.start();
            httpClient.getProtocolHandlers().remove(WWWAuthenticationProtocolHandler.NAME);
            logger.info("Initializing the binding, with config: {}", getConfig());
        } catch (Exception e) {
            logger.error("Failed to start binding, e = {}", e);
            return false;
        }
        return true;
    }

    @Nullable
    private String getToken() {
        synchronized (tokenLock) {
            return token;
        }
    }

    public UniFiProtectStatus login() {
        String token = getToken();
        return login(token);
    }

    private void loginFailed() {
        logger.debug("Login attempt failed.");
        // Something must probably be done to make the binding go into error state "cleanly"...?
    }

    private UniFiProtectStatus login(@Nullable String oldToken) {
        String newToken;
        synchronized (tokenLock) {
            if (oldToken == null || oldToken.equals(token)) {
                UniFiProtectLoginRequest loginRequest = new UniFiProtectLoginRequest(httpClient, getConfig());
                UniFiProtectStatus sendStatus = loginRequest.sendRequest();
                if (!requestSuccessFullySent(sendStatus)) {
                    loginFailed();
                    return sendStatus;
                }
                token = loginRequest.getToken();
            }
            newToken = token;
        }
        if (newToken == null || newToken.isBlank()) {
            loginFailed();
            return UniFiProtectStatus.STATUS_TOKEN_MISSING;
        }
        return UniFiProtectStatus.STATUS_SUCCESS_LOGIN;
    }

    protected UniFiProtectStatus refreshBootstrap(String bootstrapJsonContent) {
        boolean bootstrapParseSuccess = getUniFiProtectJsonParser().parseBootstrap(bootstrapJsonContent);
        if (logger.isDebugEnabled()) {
            try {
                final File tmpFile = File.createTempFile("bootstrap", ".json");
                UniFiProtectUtil.writeFile(tmpFile, bootstrapJsonContent.getBytes());
                logger.debug("Wrote bootstrap to temp file: {}", tmpFile.getAbsolutePath());
            } catch (IOException e) {
                logger.debug("Failed to write bootstrap", e);
            }
        }
        if (!bootstrapParseSuccess) {
            return UniFiProtectStatus.STATUS_EXECUTION_FAULT;
        }
        UniFiProtectCamera[] allCameras = getUniFiProtectJsonParser().getCamerasFromBootstrap();
        if (allCameras == null) {
            return UniFiProtectStatus.STATUS_EXECUTION_FAULT;
        }
        getCameraInsightCache().clear();
        getCameraInsightCache().putAll(Arrays.asList(allCameras));
        logger.debug("Put all size: {}", getCameraInsightCache().getCameras().size());
        UniFiProtectNvrDevice newDevice = getUniFiProtectJsonParser().getNvrDeviceFromBootstrap();
        synchronized (this) {
            nvrDevice = newDevice;
        }
        logger.debug("UniFiProtectNvrDevice: {}", newDevice);
        if (newDevice == null) {
            return UniFiProtectStatus.STATUS_EXECUTION_FAULT;
        }

        UniFiProtectNvrUser[] nvrUsersFromJson = getUniFiProtectJsonParser().getNvrUsersFromBootstrap();
        Optional<@Nullable UniFiProtectNvrUser> findAny = Arrays.stream(nvrUsersFromJson)
                .filter(u -> (u.getLocalUsername() != null && u.getLocalUsername().equals(getConfig().getUserName()))
                        || u.getFirstName() != null && u.getFirstName().toLowerCase().equals(getConfig().getUserName()))
                .findAny();
        UniFiProtectNvrUser newUser;
        try {
            newUser = findAny.get();
        } catch (NoSuchElementException x) {
            logger.error("Could not find any valid user. Looking for: {}", getConfig().getUserName());
            Arrays.stream(nvrUsersFromJson).forEach(user -> logger.debug("Users in response: {}", user));
            logger.debug("Json response: {}", bootstrapJsonContent);
            return UniFiProtectStatus.STATUS_TOKEN_MISSING; // Should be something else - user missing?
        }
        String localUsername = newUser.getLocalUsername();
        if (localUsername == null || localUsername.isBlank()) {
            String firstName = newUser.getFirstName();
            if (firstName == null || firstName.isBlank()) {
                return UniFiProtectStatus.STATUS_TOKEN_MISSING; // Should be something else - local user missing?
            }
            newUser.setLocalUsername(firstName.toLowerCase(Locale.ROOT)); // Ugly workaround for localusername being
                                                                          // null in response
        }
        synchronized (this) {
            nvrUser = newUser;
        }
        if (logger.isDebugEnabled()) {
            logger.debug("UniFiProtectNvrUser: {}", newUser);
            logger.debug("Login Token Success: {}", getToken());
        }
        return UniFiProtectStatus.STATUS_SUCCESS;
    }

    protected UniFiProtectStatus refreshBootstrap() {
        String token = getToken();
        UniFiProtectBootstrapRequest request = new UniFiProtectBootstrapRequest(httpClient, getConfig(), token);
        UniFiProtectStatus bootStrapRequestStatus = request.sendRequest();
        if (!requestSuccessFullySent(bootStrapRequestStatus)) {
            UniFiProtectStatus status = login(token);
            if (status.getStatus() == SendStatus.SUCCESS) {
                token = getToken();
                request = new UniFiProtectBootstrapRequest(httpClient, getConfig(), token);
                bootStrapRequestStatus = request.sendRequest();
            } else {
                return bootStrapRequestStatus;
            }
        }
        logger.debug("Request is ok, parsing cameras");
        final String bootstrapJsonContent = request.getJsonContent();
        if (bootstrapJsonContent == null) {
            logger.error("Got null response when refreshing bootstrap");
            return UniFiProtectStatus.STATUS_EXECUTION_FAULT;
        }
        return refreshBootstrap(bootstrapJsonContent);
    }

    public UniFiProtectStatus refreshEvents() {
        UniFiProtectEventsRequest eventsRequest = new UniFiProtectEventsRequest(httpClient, getConfig(), getToken());
        UniFiProtectStatus sendStatus = eventsRequest.sendRequest();
        if (!requestSuccessFullySent(sendStatus)) {
            UniFiProtectStatus status = login(token);
            if (status.getStatus() == SendStatus.SUCCESS) {
                token = getToken();
                eventsRequest = new UniFiProtectEventsRequest(httpClient, getConfig(), token);
                sendStatus = eventsRequest.sendRequest();
            } else {
                return sendStatus;
            }
        }
        final String jsonContent = eventsRequest.getJsonContent();
        if (jsonContent == null) {
            logger.error("Failed to refresh events, since request resulted in null response");
            return UniFiProtectStatus.STATUS_EXECUTION_FAULT;
        }
        logger.debug("Got events json: {}", jsonContent);
        final UniFiProtectEvent[] events = getUniFiProtectJsonParser().getEventsFromJson(jsonContent);
        getEventCache().clear();
        getEventCache().putAll(Arrays.asList(events));
        return sendStatus;
    }

    private UniFiProtectEventCache getEventCache() {
        return eventCache;
    }

    public UniFiProtectStatus refreshProtect() {
        UniFiProtectStatus status = null;
        String token = getToken();
        if (token == null || token.isBlank()) {
            status = login(token);
            // TODO: Refresh websocket as well
        }
        if (status != null && status.getStatus() != SendStatus.SUCCESS) {
            logger.error("Failed to updated Cameras since we can't seem to login status: {}", status.getStatus());
            logger.debug("Status message: {} exception: {}", status.getMessage(),
                    status.getException() != null ? status.getException().toString() : "");
            return status;
        }
        UniFiProtectStatus refreshBootstrap = refreshBootstrap();
        if (refreshBootstrap.getStatus() == SendStatus.SUCCESS) {
            logger.debug("Successfully refreshed bootstrap");
        }

        return status == null ? refreshBootstrap : status;
    }

    public UniFiProtectCameraCache getCameraInsightCache() {
        return cameraInsightCache;
    }

    public UniFiProtectStatus start() {
        return login(null);
    }

    public @Nullable UniFiProtectCamera getCamera(UniFiProtectBaseThingConfig config) {
        if (logger.isDebugEnabled()) {
            logger.debug("getCamera cache configMac: {}", config.getMac());
            logger.debug("getCamera CameraInsightCache: {}", cameraInsightCache.toString());
            logger.debug("getCamera camera: {}", cameraInsightCache.getCamera(config.getMac()));
        }
        return cameraInsightCache.getCamera(config.getMac());
    }

    public @Nullable UniFiProtectNvrDevice getNvrDevice() {
        synchronized (this) {
            return nvrDevice;
        }
    }

    public void setStatusLightOn(UniFiProtectCamera camera, boolean enabled) {
        String cameraId = camera != null ? camera.getId() : null;
        if (cameraId == null) {
            logger.error("Failed to set status light on, camera has null fields: {}", camera);
            return;
        }
        UniFiProtectStatusLightRequest request = new UniFiProtectStatusLightRequest(httpClient, cameraId, getConfig(),
                getToken(), enabled);
        if (!requestSuccessFullySent(request.sendRequest())) {
            UniFiProtectStatus status = login(token);
            if (status.getStatus() == SendStatus.SUCCESS) {
                token = getToken();
                request = new UniFiProtectStatusLightRequest(httpClient, cameraId, getConfig(), token, enabled);
                request.sendRequest();
            } else {
                return;
            }
        }
        String jsonContent = request.getJsonContent();
        logger.debug("StatusLight on result jsonResult: {}", jsonContent);
    }

    public void rebootCamera(UniFiProtectCamera camera) {
        String cameraId = camera != null ? camera.getId() : null;
        if (cameraId == null) {
            logger.error("Failed to reoobt camera since fields are null: {}", camera);
            return;
        }
        UniFiProtectRebootCameraRequest request = new UniFiProtectRebootCameraRequest(httpClient, cameraId, getConfig(),
                getToken());
        if (!requestSuccessFullySent(request.sendRequest())) {
            UniFiProtectStatus status = login(token);
            if (status.getStatus() == SendStatus.SUCCESS) {
                token = getToken();
                request = new UniFiProtectRebootCameraRequest(httpClient, cameraId, getConfig(), token);
                request.sendRequest();
            } else {
                return;
            }
        }
        String jsonContent = request.getJsonContent();
        logger.debug("Reboot camera Result: {}", jsonContent);
    }

    public void setRecordingMode(UniFiProtectCamera camera, UniFiProtectRecordingMode recordingMode) {
        if (recordingMode == UniFiProtectRecordingMode.INVALID) {
            logger.error("Invalid recording mode, ignored");
            return;
        }

        String cameraId = camera != null ? camera.getId() : null;
        if (cameraId == null) {
            logger.error("Failed to set Recording mode since camera field is null: {}", camera);
            return;
        }

        UniFiProtectRecordingModeRequest request = new UniFiProtectRecordingModeRequest(httpClient, cameraId,
                getConfig(), getToken(), recordingMode);
        if (!requestSuccessFullySent(request.sendRequest())) {
            UniFiProtectStatus status = login(token);
            if (status.getStatus() == SendStatus.SUCCESS) {
                token = getToken();
                request = new UniFiProtectRecordingModeRequest(httpClient, cameraId, getConfig(), token, recordingMode);
                request.sendRequest();
            } else {
                return;
            }
        }
        String jsonContent = request.getJsonContent();
        logger.debug("Set Recording mode on camera Result: {}", jsonContent);
    }

    public void turnOnOrOffAlerts(boolean enable) {
        UniFiProtectNvrUser user = getNvrUser();
        if (user == null) {
            logger.error("No user set for UniFiProtect, can't turn on or off");
            return;
        }
        String id = user.getId();
        if (id != null && !id.isEmpty()) {
            UniFiProtectAlertsRequest request = new UniFiProtectAlertsRequest(httpClient, getConfig(), getToken(), id,
                    enable);
            if (!requestSuccessFullySent(request.sendRequest())) {
                UniFiProtectStatus status = login(token);
                if (status.getStatus() == SendStatus.SUCCESS) {
                    token = getToken();
                    request = new UniFiProtectAlertsRequest(httpClient, getConfig(), token, id, enable);
                    request.sendRequest();
                } else {
                    return;
                }
            }
            String jsonContent = request.getJsonContent();
            logger.debug("Enable Alerts result jsonResult: {}", jsonContent);
        }
    }

    public void setIrMode(UniFiProtectCamera camera, UniFiProtectIrMode irMode) {
        if (irMode == UniFiProtectIrMode.INVALID) {
            logger.error("Invalid recording mode, ignored");
            return;
        }
        String cameraId = camera != null ? camera.getId() : null;
        if (cameraId == null) {
            logger.error("Failed to set ir mode camera field is null: {}", camera);
            return;
        }

        UniFiProtectIrModeRequest request = new UniFiProtectIrModeRequest(httpClient, cameraId, getConfig(), getToken(),
                irMode);

        if (!requestSuccessFullySent(request.sendRequest())) {
            UniFiProtectStatus status = login(token);
            if (status.getStatus() == SendStatus.SUCCESS) {
                token = getToken();
                request = new UniFiProtectIrModeRequest(httpClient, cameraId, getConfig(), token, irMode);
                request.sendRequest();
            } else {
                return;
            }
        }
        String jsonContent = request.getJsonContent();
        logger.debug("Set IR mode on camera Result: {}", jsonContent);
    }

    public void turnOnOrOffHdrMode(UniFiProtectCamera camera, boolean enable) {
        final String cameraId = camera.getId();
        if (cameraId == null) {
            logger.error("Failed to set hdr mode, camera field is missing: {}", camera);
            return;
        }
        UniFiProtectHdrModeRequest request = new UniFiProtectHdrModeRequest(httpClient, cameraId, getConfig(),
                getToken(), enable);
        if (!requestSuccessFullySent(request.sendRequest())) {
            UniFiProtectStatus status = login(token);
            if (status.getStatus() == SendStatus.SUCCESS) {
                token = getToken();
                request = new UniFiProtectHdrModeRequest(httpClient, cameraId, getConfig(), token, enable);
                request.sendRequest();
            } else {
                return;
            }
        }
        String jsonContent = request.getJsonContent();
        logger.debug("Hdr mode result jsonResult: {}", jsonContent);
    }

    public void turnOnOrOffPrivacyZone(UniFiProtectCamera camera, boolean enable) {
        final String cameraId = camera.getId();
        if (cameraId == null) {
            logger.error("Failed to set privacy zone, camera field is missing: {}", camera);
            return;
        }
        UniFiProtectPrivacyZoneRequest request = new UniFiProtectPrivacyZoneRequest(httpClient, cameraId, getConfig(),
                getToken(), enable);
        if (!requestSuccessFullySent(request.sendRequest())) {
            UniFiProtectStatus status = login(token);
            if (status.getStatus() == SendStatus.SUCCESS) {
                token = getToken();
                request = new UniFiProtectPrivacyZoneRequest(httpClient, cameraId, getConfig(), token, enable);
                request.sendRequest();
            } else {
                return;
            }
        }
        String jsonContent = request.getJsonContent();
        logger.debug("Privacy result jsonResult: {}", jsonContent);
    }

    public void turnOnOrOffMotionDetection(UniFiProtectCamera camera, boolean enable) {
        final String cameraId = camera.getId();
        if (cameraId == null) {
            logger.error("Failed to set motion detection, camera field is missing: {}", camera);
            return;
        }
        UniFiProtectMotionDetectionRequest request = new UniFiProtectMotionDetectionRequest(httpClient, cameraId,
                getConfig(), getToken(), enable);
        if (!requestSuccessFullySent(request.sendRequest())) {
            UniFiProtectStatus status = login(token);
            if (status.getStatus() == SendStatus.SUCCESS) {
                token = getToken();
                request = new UniFiProtectMotionDetectionRequest(httpClient, cameraId, getConfig(), token, enable);
                request.sendRequest();
            } else {
                return;
            }
        }
        String jsonContent = request.getJsonContent();
        logger.debug("Motion Detection result jsonResult: {}", jsonContent);
    }

    public void turnOnOrOffHighFpsMode(UniFiProtectCamera camera, boolean enable) {
        String cameraId = camera != null ? camera.getId() : null;
        if (cameraId == null) {
            logger.error("Failed to turn on high Fps mode, camera field is null: {}", camera);
            return;
        }
        UniFiProtectHighFpsModeRequest request = new UniFiProtectHighFpsModeRequest(httpClient, cameraId, getConfig(),
                getToken(), enable);
        if (!requestSuccessFullySent(request.sendRequest())) {
            UniFiProtectStatus status = login(token);
            if (status.getStatus() == SendStatus.SUCCESS) {
                token = getToken();
                request = new UniFiProtectHighFpsModeRequest(httpClient, cameraId, getConfig(), token, enable);
                request.sendRequest();
            } else {
                return;
            }
        }
        String jsonContent = request.getJsonContent();
        logger.debug("High FPS mode result jsonResult: {}", jsonContent);
    }

    public @Nullable UniFiProtectImage getThumbnail(UniFiProtectCamera camera, UniFiProtectEvent event) {
        final String thumbnail = event != null ? event.getThumbnail() : null;
        if (thumbnail == null || thumbnail.isEmpty()) {
            logger.debug("Could not find any thumbnails in events for camera: {}", camera.getId());
            return null;
        }
        UniFiProtectImage thumbnailImage = null;
        UniFiProtectThumbnailRequest request = new UniFiProtectThumbnailRequest(httpClient, camera, getToken(),
                thumbnail, getConfig());
        if (!requestSuccessFullySent(request.sendRequest())) {
            UniFiProtectStatus status = login(token);
            if (status.getStatus() == SendStatus.SUCCESS) {
                token = getToken();
                request = new UniFiProtectThumbnailRequest(httpClient, camera, token, thumbnail, getConfig());
                request.sendRequest();
            } else {
                return null;
            }
        }
        if (UniFiProtectUtil.requestHasContentOfSize(request, IMAGE_MIN_SIZE)) {
            byte[] data = request.getResponse().getContent();
            // logger.debug("Content size for thumbnail request: {}", data.length);
            final String cameraId = camera.getId();
            if (cameraId == null) {
                logger.error("CameraId is null, cannot download thumbnail: {}", camera);
                return null;
            }
            File thumbnailFile = UniFiProtectUtil.writeThumbnailToImageFolder(getConfig().getImageFolder(), cameraId,
                    event.getType(), request.getResponse().getContent());
            if (thumbnailFile != null) {
                thumbnailImage = new UniFiProtectImage(UniFiProtectImageHandler.IMAGE_JPEG, thumbnailFile);
                logger.debug("Wrote thumbnail file: {} size: {}", thumbnailFile.getAbsolutePath(), data.length);
            }
        }
        return thumbnailImage;
    }

    private boolean requestSuccessFullySent(UniFiProtectStatus status) {
        switch (status.getStatus()) {
            case EXECUTION_FAULT:
            case INTERRUPTED:
            case NOT_SENT:
            case TIMEOUT:
            case TOKEN_MISSING:
            case HTTP_ERROR:
            case INVALID_TOKEN:
                logger.debug("Request failed reason: {} message: {}", status.getStatus().name(), status.getMessage(),
                        status.getException());
                return false;
            case SUCCESS:
                logger.debug("Successfullt sent request");
                return true;
            default:
                logger.debug("Unhandled case: {} message: {}", status.getStatus().name(), status.getMessage(),
                        status.getException());
                return true;
        }
    }

    public @Nullable UniFiProtectEvent getLastMotionEvent(UniFiProtectCamera camera) {
        final String id = camera != null ? camera.getId() : null;
        return (id != null) ? eventCache.getLatestMotionEvent(id) : null;
    }

    public @Nullable UniFiProtectImage getHeatmap(UniFiProtectCamera camera, UniFiProtectEvent event) {
        String heatmap = event != null ? event.getHeatmap() : null;
        final String cameraId = camera.getId();
        if (cameraId == null) {
            logger.error("CameraId is null: {}", camera);
            return null;
        }
        if (heatmap == null || heatmap.isEmpty()) {
            logger.warn("Could not find any heatMap in events for camera: {}", cameraId);
            return null;
        }
        UniFiProtectImage heatmapImage = null;
        UniFiProtectHeatmapRequest request = new UniFiProtectHeatmapRequest(httpClient, getToken(), heatmap,
                getConfig());
        if (!requestSuccessFullySent(request.sendRequest())) {
            UniFiProtectStatus status = login(token);
            if (status.getStatus() == SendStatus.SUCCESS) {
                token = getToken();
                request = new UniFiProtectHeatmapRequest(httpClient, token, heatmap, getConfig());
                request.sendRequest();
            } else {
                return null;
            }
        }

        if (UniFiProtectUtil.requestHasContentOfSize(request, IMAGE_MIN_SIZE)) {
            byte[] data = request.getResponse().getContent();
            File heatmapFile = UniFiProtectUtil.writeHeatmapToFile(getConfig().getImageFolder(), cameraId, data,
                    event.getType());
            if (heatmapFile != null) {
                heatmapImage = new UniFiProtectImage(UniFiProtectImageHandler.IMAGE_PNG, heatmapFile);
                logger.debug("Wrote heatmap file: {} size: {}", heatmapImage.getFile().getAbsolutePath(),
                        heatmapImage.getData().length);
            }
        } else {
            byte[] data = request.getResponse().getContent();
            logger.debug("Heatmap request resulted in a error size image");
            if (data != null) {
                try {
                    logger.debug("Heatmap data: {} {}", data.length, new String(data));
                } catch (Exception x) {
                }
            }
        }
        return heatmapImage;
    }

    public @Nullable UniFiProtectImage getSnapshot(UniFiProtectCamera camera) {
        final String cameraId = camera.getId();
        final String cameraType = camera.getType();
        if (cameraId == null || cameraType == null) {
            logger.error("Failed to get snapshot, camera field null: {}", camera);
            return null;
        }
        UniFiProtectImage snapshot = null;
        UniFiProtectSnapshotRequest request = new UniFiProtectSnapshotRequest(httpClient, cameraId, cameraType,
                getToken(), getConfig());
        if (!requestSuccessFullySent(request.sendRequest())) {
            UniFiProtectStatus status = login(token);
            if (status.getStatus() == SendStatus.SUCCESS) {
                token = getToken();
                request = new UniFiProtectSnapshotRequest(httpClient, cameraId, cameraType, token, getConfig());
                request.sendRequest();
            } else {
                return null;
            }
        }
        if (UniFiProtectUtil.requestHasContentOfSize(request, IMAGE_MIN_SIZE)) {
            logger.debug("Content size for snapshot request: {}", request.getResponse().getContent().length);
            File file = UniFiProtectUtil.writeSnapshotToFile(getConfig().getImageFolder(), cameraId,
                    request.getResponse().getContent());
            if (file != null) {
                logger.debug("Wrote snapshot file: {} size: {}", file.getAbsolutePath(), file.length());
                snapshot = new UniFiProtectImage(UniFiProtectImageHandler.IMAGE_JPEG, file);
            }
        } else {
            logger.debug("Snapshot not reccieved");
        }
        return snapshot;
    }

    public @Nullable UniFiProtectImage getAnonSnapshot(@Nullable UniFiProtectCamera camera) {
        if (camera == null) {
            return null;
        }
        final String cameraHost = camera.getHost();
        final String cameraId = camera.getId();
        if (cameraHost == null || cameraId == null) {
            logger.error("Failed to get anon snapshot, camera fields null: {}", camera);
            return null;
        }
        UniFiProtectImage anonSnapshotImage = null;
        UniFiProtectAnonymousSnapshotRequest request = new UniFiProtectAnonymousSnapshotRequest(httpClient, cameraHost,
                getConfig());
        if (!requestSuccessFullySent(request.sendRequest())) {
            UniFiProtectStatus status = login(token);
            if (status.getStatus() == SendStatus.SUCCESS) {
                token = getToken();
                request = new UniFiProtectAnonymousSnapshotRequest(httpClient, cameraHost, getConfig());
                request.sendRequest();
            } else {
                return null;
            }
        }
        if (UniFiProtectUtil.requestHasContentOfSize(request, IMAGE_MIN_SIZE)) {
            logger.debug("Content size for anon snapshot request: {}", request.getResponse().getContent().length);
            final byte[] data = request.getResponse().getContent();
            File file = UniFiProtectUtil.writeAnonSnapshotToFile(getConfig().getImageFolder(), cameraId, data);
            if (file != null) {
                anonSnapshotImage = new UniFiProtectImage(UniFiProtectImageHandler.IMAGE_JPEG, file);
                logger.debug("Wrote anon snapshot file: {} size: {}", file.getAbsolutePath(), data.length);
            }
        }
        return anonSnapshotImage;
    }

    public @Nullable UniFiProtectNvrUser getNvrUser() {
        synchronized (this) {
            return nvrUser;
        }
    }

    public UniFiProtectNvrThingConfig getConfig() {
        return config;
    }

    public HttpClient getHttpClient() {
        return httpClient;
    }

    public @Nullable UniFiProtectEvent getLastMotionEventFromCamera(UniFiProtectCamera camera) {
        final String cameraId = camera != null ? camera.getId() : null;
        return cameraId != null ? eventCache.getLatestMotionEvent(cameraId) : null;
    }

    public @Nullable UniFiProtectEvent getLastRingEventFromCamera(UniFiProtectCamera camera) {
        final String cameraId = camera != null ? camera.getId() : null;
        return cameraId != null ? eventCache.getLatestRingEvent(cameraId) : null;
    }

    public @Nullable UniFiProtectEvent getEventFromId(String id) {
        return eventCache.getEventFromEventId(id);
    }

    public Collection<UniFiProtectEvent> getEvents() {
        return eventCache.getEvents();
    }

    public UniFiProtectJsonParser getUniFiProtectJsonParser() {
        return uniFiProtectJsonParser;
    }

    public void setLcdMessage(UniFiProtectCamera camera, UniFiProtectLcdMessage lcdMessage) {
        String cameraId = camera != null ? camera.getId() : null;
        if (cameraId == null) {
            logger.error("Failed to set LCD, camera field is null: {}", camera);
            return;
        }
        UniFiProtectLcdMessageRequest request = new UniFiProtectLcdMessageRequest(httpClient, cameraId, getConfig(),
                getToken(), lcdMessage);
        if (!requestSuccessFullySent(request.sendRequest())) {
            UniFiProtectStatus status = login(token);
            if (status.getStatus() == SendStatus.SUCCESS) {
                token = getToken();
                request = new UniFiProtectLcdMessageRequest(httpClient, cameraId, getConfig(), token, lcdMessage);
                request.sendRequest();
            } else {
                return;
            }
        }
        String jsonContent = request.getJsonContent();
        logger.debug("LcdMessage result jsonResult: {}", jsonContent);
    }

    public void setSmartDetectTypes(UniFiProtectCamera camera, UniFiProtectSmartDetectTypes smartDetectTypes) {
        String cameraId = camera != null ? camera.getId() : null;
        if (cameraId == null) {
            logger.error("Failed to set LCD, camera field is null: {}", camera);
            return;
        }
        UniFiProtectSmartDetectRequest request = new UniFiProtectSmartDetectRequest(httpClient, cameraId, getConfig(),
                getToken(), smartDetectTypes);
        if (!requestSuccessFullySent(request.sendRequest())) {
            UniFiProtectStatus status = login(token);
            if (status.getStatus() == SendStatus.SUCCESS) {
                token = getToken();
                request = new UniFiProtectSmartDetectRequest(httpClient, cameraId, getConfig(), token,
                        smartDetectTypes);
                request.sendRequest();
            } else {
                return;
            }
        }
        String jsonContent = request.getJsonContent();
        logger.debug("smartDetectTypes result jsonResult: {}", jsonContent);
        camera.setSmartDetectObjectTypes(smartDetectTypes);
    }

    public void setStatusSounds(UniFiProtectCamera camera, boolean enabled) {
        String cameraId = camera != null ? camera.getId() : null;
        if (cameraId == null) {
            logger.error("Failed to set status sounds on, camera has null fields: {}", camera);
            return;
        }
        UniFiProtectStatusSoundsRequest request = new UniFiProtectStatusSoundsRequest(httpClient, cameraId, getConfig(),
                getToken(), enabled);
        if (!requestSuccessFullySent(request.sendRequest())) {
            UniFiProtectStatus status = login(token);
            if (status.getStatus() == SendStatus.SUCCESS) {
                token = getToken();
                request = new UniFiProtectStatusSoundsRequest(httpClient, cameraId, getConfig(), token, enabled);
                request.sendRequest();
            } else {
                return;
            }
        }
        String jsonContent = request.getJsonContent();
        logger.debug("StatusSounds on result jsonResult: {}", jsonContent);
    }

    public void setChime(UniFiProtectCamera camera, int chimeDuration) {
        String cameraId = camera != null ? camera.getId() : null;
        if (cameraId == null) {
            logger.error("Failed to set chime, camera has null fields: {}", camera);
            return;
        }
        UniFiProtectChimeRequest request = new UniFiProtectChimeRequest(httpClient, cameraId, getConfig(), getToken(),
                chimeDuration);
        if (!requestSuccessFullySent(request.sendRequest())) {
            UniFiProtectStatus status = login(token);
            if (status.getStatus() == SendStatus.SUCCESS) {
                token = getToken();
                request = new UniFiProtectChimeRequest(httpClient, cameraId, getConfig(), token, chimeDuration);
                request.sendRequest();
            } else {
                return;
            }
        }
        String jsonContent = request.getJsonContent();
        logger.debug("ChimeRequest on result jsonResult: {}", jsonContent);
    }
}
