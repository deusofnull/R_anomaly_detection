library(methods)
library(parsedate)
library(jsonlite)
library(lubridate)
library(datasets)
library(graphics)
library(grDevices)

library(stats)
library(utils)

library(AnomalyDetection)
library(elastic)

generateRequestBody <- function(){
  
  reqBody = list()
  reqBody[['fields']] <- list("netflow.ipv4_dst_addr",
                              "netflow.ipv4_src_addr",
                              "netflow.l4_dst_port",
                              "netflow.l4_src_port",
                              "netflow.in_bytes",
                              "netflow.in_pkts",
                              "@timestamp")
  
  reqBody['size'] = 1
  
  reqBody[['filter']] = list(
    "range"= list( 
      "@timestamp"=list(
        "gte"=getTimeNeg1H(),
        "lte"=getTime(),
        "time_zone"="-05:00"
      )))
  
  return(prettify(toJSON(reqBody, auto_unbox = TRUE),indent = 4))
}

generateRequestBodyUTC <- function(size){
  
  reqBody = list()
  reqBody[['fields']] <- list("netflow.ipv4_dst_addr",
                              "netflow.ipv4_src_addr",
                              "netflow.l4_dst_port",
                              "netflow.l4_src_port",
                              "netflow.in_bytes",
                              "netflow.in_pkts",
                              "@timestamp")
  
  reqBody['size'] = size
  
  reqBody[['filter']] = list(
    "range"= list( 
      "@timestamp"=list(
        "gte"=getUTCTimeNeg1H(),
        "lte"=getUTCTime()
      )))
  
  return(prettify(toJSON(reqBody, auto_unbox = TRUE),indent = 4))
}

getCurrentTime <-function() {
  currentTimestamp <- parsedate::parse_date(as.character(Sys.time()))
  return(currentTimestamp)
}
getCurrentTimes <- function() {
  currentTimestamp <- parsedate::parse_date(as.character(Sys.time()))
  return(currentTimestamp)
}

getTime <- function(){
  curTime <- format_iso_8601(parse_iso_8601(Sys.time()))
  return(curTime)
}

getTimeNeg1H <- function () {
  curTime = Sys.time()
  neg1t <- as.POSIXct(curTime, tz="-05:00") - as.difftime(1, unit="hours")
  neg1t <- format_iso_8601(parse_iso_8601(neg1t))
  
  return(neg1t)
}

getTimestamp <- function(es_out){
  timestamp <- parsedate::parse_date(out$hits$hits[[1]][6][[1]]$`@timestamp`[[1]])
  return(timestamp)
}

getTimestampNeg1H <- function () {
  curTime = Sys.time()
  neg1t <- as.POSIXct(curTime, tz="-05:00") - as.difftime(1, unit="hours")
  neg1t <- format_iso_8601(parse_iso_8601(neg1t))
  
  return(neg1t)
}

getUTCTime <- function(){
  curTime <- as.POSIXct(parse_iso_8601(Sys.time()))
  return(curTime)
}

getUTCTimeNeg1H <- function(){
  curTime <- as.POSIXct(parse_iso_8601(Sys.time())) - as.difftime(1, unit="hours")
  return(format_iso_8601(curTime))
}

hack_schedule_method <- function() {
  # this will run anomaly detection on the hour every hour after start
  repeat{
    startTime <- Sys.time()
    run_anomaly_detection()
    sleepTime <- startTime + 36000 - Sys.time()
    if (sleepTime > 0){
      Sys.sleep(sleepTime)
    }
  }
}

input_anoms_to_es_in <- function(anoms, es_out){
  
  start_time <- Sys.time()
  
  anoms_vec <- c()
  anoms_vec <- c(anoms_vec, anoms$anoms[,])
  
  #print(length(anoms_vec$anoms))
  #print(length(anoms_vec$index))
  
  
  # first 0 out all documents netflow.anom_detected fields
  for (i in seq(from=1, to=length(es_out$hits$hits), by=1)){
    es_out$hits$hits[[i]]$fields$netflow.anom_detected <- 0
  }
  
  for (i in seq(from=1, to=length(anoms_vec$index), by=1)){
    #print(anoms_vec$index[i])
    #print(anoms_vec$anoms[i])
    #print("Visual test: ")
    #print(es_out$hits$hits[[anoms_vec$index[i]]]$fields$`@timestamp`[[1]])
    #print(es_out$hits$hits[[anoms_vec$index[i]]]$fields$netflow.in_bytes)
    
    #add anom value = 1 to each es_out doc that is in anoms_vec$index
    es_out$hits$hits[[ anoms_vec$index[i] ]]$fields$netflow.anom_detected <- list(1)
    
    #print(prettify(toJSON(es_out$hits$hits[[anoms_vec$index[i]]]$fields), indent=2))
  }
  
  end_time <- Sys.time()
  
  elapsed_time <- end_time - start_time
  print(paste("input_anoms_to_es_in() Elapsed Time: ", elapsed_time))
  return(es_out)
}

munge_es_out_anomalyPrcs_format <- function(es_out){
  
  start_time <- Sys.time()
  
  # puts es_out document fields @timestamp and netflow.in_bytes into a dataframe...
  
  #Adjust timestamp from UTC to EDT
  adjusted_timestamps <- sapply(
    es_out$hits$hits, 
    function(x) x$fields$`@timestamp`[[1]] <- format_iso_8601(
      as.POSIXct(
        parse_iso_8601(
          x$fields$`@timestamp`[[1]]
        ) - as.difftime(4, units="hours")
      )
    )
  )
  
  #print(adjusted_timestamps)
  
  timestamp_list <- lubridate::ymd_hms(sapply(adjusted_timestamps, 
                                              function(x) x)
  )
  in_bytes_list <- sapply(es_out$hits$hits, 
                          function(x) x$fields$netflow.in_bytes[[1]])
  
  
  netflow_dataframe <- data.frame(timestamp_list, in_bytes_list)
  
  end_time <- Sys.time()
  
  elapsed_time <- end_time - start_time
  
  print(paste("munge_es_out_anomalyPrcs_format() Elapsed Time: ", elapsed_time))
  
  return(netflow_dataframe)
}

munge_es_out_timestamps <- function(es_out) {
  # Munges timestamps in all documents of resulted ES dataset 
  # input es_out$hits$hits$fields$`@timestamp` timezone format is UTC
  # output es_out$hits$hits$fields$`@timestamp` timezone format is EDT
  
  lapply(
    es_out$hits$hits, 
    function(x) x$fields$`@timestamp`[[1]] <- format_iso_8601(
      as.POSIXct(
        parse_iso_8601(
          x$fields$`@timestamp`[[1]]
        ) - as.difftime(4, units="hours")
      )
    )
  )
  
  return(es_out)
}

munge_es_out_timestamps1 <- function(es_out) {
  # Munges timestamps in all documents of resulted ES dataset 
  # input es_out$hits$hits$fields$`@timestamp` timezone format is UTC
  # output es_out$hits$hits$fields$`@timestamp` timezone format is EDT
  
  sapply(
    es_out$hits$hits, 
    function(x) x$fields$`@timestamp`[[1]] <- format_iso_8601(
      as.POSIXct(
        parse_iso_8601(
          x$fields$`@timestamp`[[1]]
        ) - as.difftime(4, units="hours")
      )
    )
  )
  
  return(es_out)
}

post_es_in <- function(es_in){
  
  start_time <- Sys.time()
  
  #make index name
  #TODO: *****Ensure documents end up in the correct date index... ******
  # because this will not do for times midnight -4 hours... 
  index_date <- toString(Sys.Date())
  index_name <- paste("anomaly_detection-", index_date, sep="")
  
  for(i in seq(from=1, to=length(es_in$hits$hits), by=1)){
    doc_id = runif(1, 1000000, 100000000)
    
    docs_create(index=index_name, id=doc_id, type="netflow-anomaly", body=es_in$hits$hits[[i]]$fields)
  }
  
  end_time <- Sys.time()
  
  elapsed_time <- end_time - start_time 
  
  print(paste("post_es_in() Elapsed Time: ", elapsed_time))
  
}

queryES <- function(size){
  connect(es_base = "http://10.197.11.174", es_port=9200)
  start_time <- Sys.time()
  
  # queries ES in UTC
  #index <- "logstash-client-netflow-*"
  index <- "client_netflow-*"
  query_size <- size
  requestBody <- generateRequestBodyUTC(query_size)
  es_out <- Search(index=index, body=requestBody)
  # es_out <- start_time
  
  end_time <- Sys.time()
  elapsed_time <- end_time - start_time
  print(paste("queryEs() Elapsed Time: ", elapsed_time))
  print (paste("Fetched Documents Total: "), str(length(es_out$hits$hits)))
  
  return(es_out)
}

run_anom_detector <- function(es_out_df){
  start_time <- Sys.time()
  
  anoms <- AnomalyDetectionVec(es_out_df[,2], period=30, plot=TRUE)
  
  end_time <- Sys.time()
  
  elapsed_time <- end_time - start_time 
  
  print(paste("run_anom_detector() Elapsed Time: ", elapsed_time))
  
  return(anoms)
  
}

run_anomaly_detection <- function(){ 
  
  # How this all works: 
  # Note:  I still need to make this grab ALL documents between these two time points
  # 1 - query ES for documents using generateRequestBodyUTC(size) to build a request body search
  # function: queryES(size)
  # 2- normalize ES data, preparing it for anomaly detection, put es_out into dataframe of 
  # timestamp | netflow.in_bytes
  # function: munge_es_out_anomalyPrcs_format(es_out)
  # 2 - run AnomalyDetectionVec on netflow.in_bytes column of data frame 
  # function: AnomalyDetectionVec(es_out_df[,2], period=30, plot=TRUE)
  # NOTE/TODO: experiment with period values and other params of anomDetcVec
  # 3 - build es_in by marking all anomalous events with a 1 in netflow.anom_detected field
  # function: input_anoms_to_es_in(anoms, es_out)
  # 4 - post es_in to ES for storage and Kibana viewing
  # function: post_es_in(es_in)
  
  es_out <- queryES(10000) #make grab all instead of set value per hour
  
  es_out_df <- munge_es_out_anomalyPrcs_format(es_out)
  
  anoms <- run_anom_detector(es_out_df)
  
  es_in <- input_anoms_to_es_in(anoms, es_out)
  
  post_es_in(es_in)
}

run_anomaly_detection()
