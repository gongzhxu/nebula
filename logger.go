package nebula

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
)

func configLogger(l *logrus.Logger, c *config.C) error {
	// set up our logging level
	logLevel, err := logrus.ParseLevel(strings.ToLower(c.GetString("logging.level", "info")))
	if err != nil {
		return fmt.Errorf("%s; possible levels: %s", err, logrus.AllLevels)
	}
	l.SetLevel(logLevel)

	disableTimestamp := c.GetBool("logging.disable_timestamp", false)
	timestampFormat := c.GetString("logging.timestamp_format", "")
	fullTimestamp := (timestampFormat != "")
	if timestampFormat == "" {
		timestampFormat = time.RFC3339
	}

	logFormat := strings.ToLower(c.GetString("logging.format", "text"))
	switch logFormat {
	case "text":
		l.Formatter = &logrus.TextFormatter{
			TimestampFormat:  timestampFormat,
			FullTimestamp:    fullTimestamp,
			DisableTimestamp: disableTimestamp,
		}
	case "json":
		l.Formatter = &logrus.JSONFormatter{
			TimestampFormat:  timestampFormat,
			DisableTimestamp: disableTimestamp,
		}
	default:
		return fmt.Errorf("unknown log format `%s`. possible formats: %s", logFormat, []string{"text", "json"})
	}

	// set up our logging file
	logFile := c.GetString("logging.file", "")
	if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			return err
		}

		l.SetOutput(f)
	}

	return nil
}
