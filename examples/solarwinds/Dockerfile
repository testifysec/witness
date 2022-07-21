# Copyright 2021 The Witness Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM golang:1.17-alpine

WORKDIR /src
RUN apk --no-cache add git pkgconfig libseccomp-dev gcc musl-dev openssl
RUN openssl genpkey -algorithm ed25519 -outform PEM -out demokey.pem && \
  openssl pkey -in demokey.pem -pubout > demokey.pub.pem
RUN git clone https://github.com/testifysec/solarsploit.git && \
  cd solarsploit && \
  go build -o ./solarsploit ./main.go

COPY ./witness.yaml ./witness.yaml
COPY ./main.go ./main.go
COPY ./witness ./witness
