// 환경 변수
require('dotenv').config();
const express = require('express');
const { GoogleGenAI } = require('@google/genai');
const cors = require('cors');

const app = express();
const port = 3000;

app.use(cors());
app.use(express.json());

// --- Gemini API 설정 ---
const GEMINI_API_KEY = process.env.AI_API_KEY;

// .env 파일에 API 키가 없다면 서버 시작 전에 오류를 발생시키고 강제종료임으로 주의하셈!!!!
if (!GEMINI_API_KEY) {
    console.error("오류: AI_API_KEY 환경 변수가 설정되지 않았습니다.");
    process.exit(1); // 서버 시작 전에 종료됨
}

// Gemini api 관련 설정임 건들지 마세요!!
// key 값 하고 모델명 임 
const ai = new GoogleGenAI({ apiKey: GEMINI_API_KEY });
const MODEL_NAME = 'gemini-2.5-flash';


/**
 * Gemini API를 호출하여 *프로그램 코드 묶음*을 분석
 * @param {string} programString - 분석할 파일 내용이 합쳐진 문자열
 * @returns {Promise<string>} - Gemini 모델의 분석 결과 (순수 JSON 문자열)
 */
async function analyzeProgramWithGemini(programString) {
    
    const prompt = `
   당신은 최고의 사이버 보안 분석가이자 숙련된 소프트웨어 아키텍트입니다.
    당신의 임무는 제공된 코드 파일을 정밀하게 분석하여 잠재적인 보안 위협, 취약점, 악의적인 행위 및 코드 품질 문제를 식별하는 것입니다.
    아래에 제공된 코드 파일을 분석하여 다음 6가지 핵심 영역에 대해 명확하게 답변하세요.
    1.  **보안 위협 (Security Threats):**
        * 금융 사기(스캠), 피싱, 랜섬웨어와 관련된 코드가 있습니까?
        * 사용자 데이터를 외부 서버로 몰래 전송(data exfiltration)하려는 시도가 있습니까?
        * 의심스러운 URL, IP 주소로의 네트워크 연결, 또는 난독화된 코드가 포함되어 있습니까?
    2.  **주요 취약점 (Key Vulnerabilities):**
        * SQL 인젝션, XSS(Cross-Site Scripting), OS 커맨드 인젝션과 같이 사용자 입력 검증이 누락되어 발생할 수 있는 취약점이 있습니까?
        * API 키, 비밀번호, 인증 토큰 등이 코드 내에 하드코딩되어 있습니까?
        * MD5, SHA1 등 취약한 암호화 알고리즘을 사용합니까?
    3.  **데이터 프라이버시 (Data Privacy):**
        * 개인 식별 정보(PII), 금융 정보, 위치 정보 등 유저의 민감한 정보를 수집합니까?
        * 수집한다면, 해당 데이터를 암호화되지 않은 상태로 제3자에게 전송합니까?
    4.  **코드 품질 및 논리 (Code Quality & Logic):**
        * 주석이나 함수명과 실제 동작이 일치하지 않는 부분이 있습니까?
        * 명백한 논리적 오류, 무한 루프 가능성, 또는 도달할 수 없는 '데드 코드(dead code)'가 있습니까?
    5.  **부적절한 콘텐츠 (Inappropriate Content):**
        * 변수명, 주석, 문자열 등에 선정적이거나 모욕적인(suggestive/obscene/offensive) 문구가 있습니까?
    6.  **구문 유효성 (Syntax Validity):**
        * 각 코드 파일이 해당 언어의 구문적으로 유효한(valid) 코드입니까?

    **답변은 반드시 한글로 Markdown 코드 블록 없이 순수한 JSON 객체(raw JSON object)로만 작성해 주세요.**
    
    --- JSON 출력 형식 (필수) ---
    {
      "runId": "analysis-${new Date().toISOString().split('T')[0]}-XXXXXXXXX",
      "status": "SUCCESS" 또는 "ERROR",
      "processedAt": "${new Date().toISOString()}",
      "finalDecision": "CRITICAL_RISK" 또는 "SECURITY_WARNING" 또는 "CONTENT_WARNING" 또는 "INVALID_FORMAT" 또는 "CLEAN",
      "summary": "프로그램 전체에 대한 분석 결과를 요약합니다. 가장 심각한 위험을 먼저 언급하세요.",
      "reportDetails": {
        "securityThreatCheck": {
          "detected": true 또는 false,
          "riskLevel": "높음" 또는 "중간" 또는 "낮음" 또는 "없음",
          "issues": ["스캠, 피싱, 데이터 탈취, 악성 URL 등 위협 관련 문제점 또는 '없음'"]
        },
        "vulnerabilityCheck": {
          "detected": true 또는 false,
          "riskLevel": "높음" 또는 "중간" 또는 "낮음" 또는 "없음",
          "issues": ["SQL 인젝션, XSS, 하드코딩된 비밀번호 등 취약점 관련 문제점 또는 '없음'"]
        },
        "privacyCheck": {
          "riskLevel": "높음" 또는 "중간" 또는 "낮음" 또는 "없음",
          "issues": ["민감 정보 수집, 제3자 전송 관련 문제점 또는 '없음'"]
        },
        "syntaxCheck": {
          "valid": true 또는 false,
          "issues": ["코드 구문 유효성 관련 문제점 또는 '모든 파일이 유효함'"]
        },
        "codeQualityCheck": {
          "detected": true 또는 false,
          "issues": ["논리적 오류, 주석 불일치, 데드 코드 등 관련 문제점 또는 '없음'"]
        },
        "contentCheck": {
          "detected": true 또는 false,
          "issues": ["선정적이거나 모욕적인 문구 관련 문제점 또는 '없음'"]
        }
      }
    }
    
    --- finalDecision 결정 로직 (필수) ---
    1.  'securityThreatCheck.detected'가 true이거나 'vulnerabilityCheck.riskLevel'이 '높음'이면 "CRITICAL_RISK"
    2.  'vulnerabilityCheck.detected'가 true (단, '높음'이 아님) 이거나 'privacyCheck.riskLevel'이 '높음' 또는 '중간'이면 "SECURITY_WARNING"
    3.  'syntaxCheck.valid'가 false이면 "INVALID_FORMAT"
    4.  'contentCheck.detected'가 true이거나 'codeQualityCheck.detected'가 true이거나 'privacyCheck.riskLevel'이 '낮음'이면 "CONTENT_WARNING"
    5.  위 1, 2, 3, 4에 해당하지 않고 모든 검사를 통과한 경우에만 "CLEAN"

    --- 분석할 프로그램 코드 () ---
    ${programString} 
    ---
    `;
    
    try {
        const response = await ai.models.generateContent({
            model: MODEL_NAME,
            contents: prompt,
            config: {
                responseMimeType: 'application/json',
            }
        });
        
        return response.text;
        
    } catch (error) {
        console.error("Gemini API 호출 오류:", error); // 여긴 터미널에 기록되는 메시지
        throw new Error("Gemini API 통신 중 문제가 발생했습니다."); // 여긴 클라이언트에게 전달되는 메시지
    }
}

// --- API 엔드포인트: POST /analyze ---
app.post('/analyze', async (req, res) => {
    
    //프론트엔드가 보낸 'codeFiles' 배열을 추출
    const { programMeta, codeFiles } = req.body;

    // 유효성 검사
    if (!codeFiles || !Array.isArray(codeFiles) || codeFiles.length === 0) {
        return res.status(400).json({ error: "분석할 'codeFiles' 배열이 요청 본문에 포함되어야 합니다." });
    }

    try {
        console.log(`[${new Date().toISOString()}] 요청 데이터 수신:`, req.body.programMeta);
        
        //모든 파일 내용을 하나의 문자열로 합침
        let programContext = `--- 프로그램 제목: ${programMeta.title} ---\n\n`;
        for (const file of codeFiles) {
            programContext += `--- 파일명: ${file.fileName} ---\n`;
            programContext += `${file.content}\n`; // 각 파일의 텍스트 내용
            programContext += `--- 파일 끝: ${file.fileName} ---\n\n`;
        }
        
        //합쳐진 'programContext' 문자열을 분석 함수로 전달
        const analysisResult = await analyzeProgramWithGemini(programContext);
        
        // Gemini 분석 결과가 순수 JSON 문자열일 것으로 예상하고 파싱
        let finalResponse;
        try {
            finalResponse = JSON.parse(analysisResult);
        } catch (e) {
            console.error("모델 응답 파싱 오류:", e);
            return res.status(500).json({
                status: "error",
                message: "Gemini 모델이 요청된 JSON 형식을 따르지 않았습니다.",
                detail: `모델 응답: ${analysisResult.substring(0, 100)}...`,
            });
        }
        
        // 최종적으로 파싱된 JSON 객체를 클라이언트에게 반환
        res.status(200).json({ 
            status: "success",
            analysis: finalResponse 
        });

    } catch (error) {
        console.error(`[${new Date().toISOString()}] 분석 중 서버 오류:`, error.message);// 터미널에 표기됨
        res.status(500).json({ 
            status: "error",
            message: "서버 내부에서 분석을 처리하는 중 오류가 발생했습니다.",// 사용자에게 보여질 메시지
            detail: error.message
        });
    }
});

// --- 서버 시작 --- (문구는 터미널에 표기되므로 신경 쓰지 않아도 되!!)
app.listen(port, () => {
    console.log(`JSON 분석 서버가 http://localhost:${port} 에서 실행 중입니다.`);
    console.log(`분석을 위해 POST 요청을 http://localhost:${port}/analyze 로 보내세요.`);
});