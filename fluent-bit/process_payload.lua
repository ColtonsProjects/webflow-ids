function process_large_payload(tag, timestamp, record)
    local new_record = {}

    -- Set the timestamp in ISO 8601 format
    new_record["ts"] = os.date("!%Y-%m-%dT%H:%M:%S.000Z", timestamp)

    -- Extract remote_ip
    if record["remote_ip"] then
        new_record["remote_ip"] = record["remote_ip"]
    elseif record["request"] and record["request"]["remote_ip"] then
        new_record["remote_ip"] = record["request"]["remote_ip"]
    else
        new_record["remote_ip"] = "unknown"
    end

    -- Extract method
    if record["method"] then
        new_record["method"] = record["method"]
    elseif record["request"] and record["request"]["method"] then
        new_record["method"] = record["request"]["method"]
    else
        new_record["method"] = "unknown"
    end

    -- Extract uri
    if record["uri"] then
        new_record["uri"] = record["uri"]
    elseif record["request"] and record["request"]["uri"] then
        new_record["uri"] = record["request"]["uri"]
    else
        new_record["uri"] = "unknown"
    end

    -- Extract user_agent
    if record["user_agent"] then
        new_record["user_agent"] = record["user_agent"]
    elseif record["request"] and record["request"]["user_agent"] then
        new_record["user_agent"] = record["request"]["user_agent"]
    else
        new_record["user_agent"] = "unknown"
    end

    -- Extract status
    if record["status"] then
        new_record["status"] = record["status"]
    elseif record["request"] and record["request"]["status"] then
        new_record["status"] = record["request"]["status"]
    else
        new_record["status"] = 0
    end

    -- Return the new, properly formatted record
    return 1, timestamp, new_record
end
